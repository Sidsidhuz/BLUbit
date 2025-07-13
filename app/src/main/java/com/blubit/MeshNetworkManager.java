package com.blubit;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class MeshNetworkManager {
    // Track all device addresses ever connected
    private final java.util.Set<String> knownDeviceAddresses = java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());
    // Unique node ID for this device
    private final String nodeId = java.util.UUID.randomUUID().toString();
    // Track recently seen message IDs to prevent loops
    private final java.util.Set<String> seenMessageIds = java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());
    private static final String TAG = "MeshNetworkManager";
    private static final String SERVICE_NAME = "BLUBIT_MESH";
    private static final UUID SERVICE_UUID = UUID.fromString("12345678-1234-5678-9012-123456789abc");
    private static final int DISCOVERY_DURATION = 120; // seconds
    private static final int MAX_HOP_COUNT = 5; // Maximum number of hops for message forwarding
    
    // Map nodeIds to device names
    private final Map<String, String> knownDeviceNames = new ConcurrentHashMap<>();

    private Context context;
    private BluetoothAdapter bluetoothAdapter;
    private CryptographyManager cryptographyManager;
    private MainActivity mainActivity;
    
    private BluetoothServerSocket serverSocket;
    private Map<String, BluetoothDevice> discoveredDevices;
    // Store RSSI for each discovered device
    private Map<String, Integer> deviceRssiMap;
    private Map<String, BluetoothSocket> connectedSockets;
    private Map<String, PublicKey> devicePublicKeys;
    private Map<String, ConnectionThread> connectionThreads;
    
    private AcceptThread acceptThread;
    private Handler mainHandler;
    private boolean isRunning = false;
    
    // Map Bluetooth address to nodeId for targeted messaging
    private Map<String, String> addressToNodeId = new ConcurrentHashMap<>();

    // Make this a private method of MeshNetworkManager
    private void updateNodeIdForAddress(String address, String nodeId) {
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Mapping nodeId " + nodeId + " to address " + address));
        String oldNodeId = addressToNodeId.get(address);
        if (oldNodeId != null && !oldNodeId.equals(nodeId)) {
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Warning: Updating existing nodeId mapping for " + address + ": " + oldNodeId + " -> " + nodeId));
        }
        addressToNodeId.put(address, nodeId);
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Updated mappings: " + addressToNodeId.toString()));
    }

    public MeshNetworkManager(MainActivity activity, BluetoothAdapter adapter, CryptographyManager cryptoManager) {
        this.context = activity;
        this.mainActivity = activity;
        this.bluetoothAdapter = adapter;
        this.cryptographyManager = cryptoManager;
        this.discoveredDevices = new ConcurrentHashMap<>();
        this.deviceRssiMap = new ConcurrentHashMap<>();
        this.connectedSockets = new ConcurrentHashMap<>();
        this.devicePublicKeys = new ConcurrentHashMap<>();
        this.connectionThreads = new ConcurrentHashMap<>();
        this.mainHandler = new Handler(Looper.getMainLooper());
        
        // Register for broadcasts when a device is discovered
        IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_FOUND);
        context.registerReceiver(discoveryReceiver, filter);
        
        // Register for broadcasts when discovery has finished
        filter = new IntentFilter(BluetoothAdapter.ACTION_DISCOVERY_FINISHED);
        context.registerReceiver(discoveryReceiver, filter);
    }
    
    public void startMeshNetwork() {
        if (isRunning) return;
        
        isRunning = true;
        startServer();
        makeDiscoverable();
    }
    
    public void stopMeshNetwork() {
        isRunning = false;
        
        // Stop server
        if (acceptThread != null) {
            acceptThread.cancel();
            acceptThread = null;
        }
        
        // Close all connections
        for (ConnectionThread thread : connectionThreads.values()) {
            thread.cancel();
        }
        connectionThreads.clear();
        connectedSockets.clear();
        
        // Stop discovery
        if (bluetoothAdapter.isDiscovering()) {
            bluetoothAdapter.cancelDiscovery();
        }
        
        try {
            context.unregisterReceiver(discoveryReceiver);
        } catch (Exception e) {
            Log.e(TAG, "Error unregistering receiver", e);
        }
    }
    
    private void startServer() {
        acceptThread = new AcceptThread();
        acceptThread.start();
    }
    
    public void makeDiscoverable() {
        Intent discoverableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
        discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, DISCOVERY_DURATION);
        mainActivity.startActivity(discoverableIntent);
    }
    
    public void startDiscovery() {
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] startDiscovery() called"));
        try {
            if (android.os.Build.VERSION.SDK_INT >= 31) {
                if (context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_SCAN) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("[DEBUG] BLUETOOTH_SCAN permission not granted"));
                    return;
                } else {
                    mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("[DEBUG] BLUETOOTH_SCAN permission granted"));
                }
            }
            if (bluetoothAdapter == null) {
                mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("[DEBUG] bluetoothAdapter is null!"));
                return;
            }
            if (bluetoothAdapter.isDiscovering()) {
                mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("[DEBUG] Already discovering, cancelling first..."));
                bluetoothAdapter.cancelDiscovery();
            }
            discoveredDevices.clear();
            boolean started = bluetoothAdapter.startDiscovery();
            mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("[DEBUG] startDiscovery() returned: " + started));
        } catch (SecurityException e) {
            mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("[DEBUG] Bluetooth discovery failed: " + e.getMessage()));
        }
    }
    
    public void connectToDevice(String deviceAddress) {
        BluetoothDevice device = discoveredDevices.get(deviceAddress);
        if (device == null) {
            // Validate Bluetooth address before using getRemoteDevice
            if (deviceAddress == null || !BluetoothAdapter.checkBluetoothAddress(deviceAddress)) {
                mainHandler.post(() -> mainActivity.displaySystemMessage("Invalid Bluetooth address: " + deviceAddress));
                return;
            }
            device = bluetoothAdapter.getRemoteDevice(deviceAddress);
        }

        if (device != null) {
            ConnectThread connectThread = new ConnectThread(device);
            connectThread.start();
        } else {
            mainHandler.post(() -> mainActivity.displaySystemMessage("Device not found: " + deviceAddress));
        }
    }
    
    public void disconnectFromDevice(String deviceAddress) {
        ConnectionThread thread = connectionThreads.get(deviceAddress);
        if (thread != null) {
            thread.cancel();
            connectionThreads.remove(deviceAddress);
            connectedSockets.remove(deviceAddress);
            devicePublicKeys.remove(deviceAddress.trim().toUpperCase()); // Clean up key mapping
        }
    }
    
    public void sendMessage(String message) {
        if (connectedSockets.isEmpty()) {
            mainHandler.post(() -> mainActivity.displaySystemMessage("No connected devices"));
            return;
        }
        // Create a unique message ID
        String messageId = java.util.UUID.randomUUID().toString();
        // Build mesh message: MSG:<msgId>:<srcNodeId>:<dstNodeId>:<encrypted>
        String dstNodeId = "ALL"; // For now, broadcast to all

        // Find the connected device with the strongest RSSI (closest node)
        String bestDeviceAddress = null;
        int bestRssi = Integer.MIN_VALUE;
        for (String deviceAddress : connectedSockets.keySet()) {
            Integer rssi = deviceRssiMap.get(deviceAddress);
            if (rssi != null && rssi > bestRssi) {
                bestRssi = rssi;
                bestDeviceAddress = deviceAddress;
            }
        }

        if (bestDeviceAddress != null) {
            final String finalBestDeviceAddress = bestDeviceAddress;
            final PublicKey finalPublicKey = devicePublicKeys.get(bestDeviceAddress);
            final int finalBestRssi = bestRssi;
            if (finalPublicKey != null) {
                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Found public key for " + finalBestDeviceAddress + ": " + cryptographyManager.getPublicKeyAsString(finalPublicKey)));
                String encryptedMessage = cryptographyManager.encryptMessage(message, finalPublicKey);
                if (encryptedMessage != null) {
                    String meshMsg = "MSG:" + messageId + ":" + nodeId + ":" + dstNodeId + ":" + encryptedMessage;
                    sendToDevice(finalBestDeviceAddress, meshMsg);
                }
            }
            mainHandler.post(() -> mainActivity.displaySystemMessage("Message sent via node with strongest RSSI: " + finalBestDeviceAddress + " (RSSI: " + finalBestRssi + ")"));
        } else {
            // Fallback: broadcast to all if no RSSI info
            for (Map.Entry<String, BluetoothSocket> entry : connectedSockets.entrySet()) {
                String deviceAddress = entry.getKey();
                PublicKey publicKey = devicePublicKeys.get(deviceAddress);
                if (publicKey != null) {
                    mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Found public key for " + deviceAddress + ": " + cryptographyManager.getPublicKeyAsString(publicKey)));
                    String encryptedMessage = cryptographyManager.encryptMessage(message, publicKey);
                    if (encryptedMessage != null) {
                        String meshMsg = "MSG:" + messageId + ":" + nodeId + ":" + dstNodeId + ":" + encryptedMessage;
                        sendToDevice(deviceAddress, meshMsg);
                    }
                }
            }
            mainHandler.post(() -> mainActivity.displaySystemMessage("Message broadcasted to all nodes (no RSSI info)"));
        }
        // Mark as seen so we don't re-broadcast our own message
        seenMessageIds.add(messageId);
        mainHandler.post(() -> mainActivity.displayOutgoingMessage(message));
    }
    
    // Send a message to a specific device by address
    public void sendMessageToDevice(String message, String deviceAddress) {
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] sendMessageToDevice: message='" + message + "', deviceAddress=" + deviceAddress));
        if (!connectedSockets.containsKey(deviceAddress)) {
            mainHandler.post(() -> mainActivity.displaySystemMessage("Device not connected: " + deviceAddress));
            return;
        }
        String messageId = java.util.UUID.randomUUID().toString();
        String dstNodeId = getNodeIdByAddress(deviceAddress);
        if (dstNodeId == null) {
            mainHandler.post(() -> mainActivity.displaySystemMessage("Node ID unknown for device: " + deviceAddress + ". Wait for handshake or try sending a message from the other device first. Will retry in 2 seconds..."));
            // Auto-retry after 2 seconds
            mainHandler.postDelayed(() -> sendMessageToDevice(message, deviceAddress), 2000);
            return;
        }
        
        PublicKey publicKey = devicePublicKeys.get(deviceAddress);
        if (publicKey == null) {
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] No public key for " + deviceAddress + ". Waiting for key exchange before sending message."));
            sendPublicKeyToPeer(deviceAddress);
            // Retry after 1 second
            mainHandler.postDelayed(() -> sendMessageToDevice(message, deviceAddress), 1000);
            return;
        }
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Found public key for " + deviceAddress + ": " + cryptographyManager.getPublicKeyAsString(publicKey)));
        String encryptedMessage = cryptographyManager.encryptMessage(message, publicKey);
        if (encryptedMessage != null) {
            String meshMsg = "MSG:" + messageId + ":" + nodeId + ":" + dstNodeId + ":" + encryptedMessage;
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Sending meshMsg to " + deviceAddress));
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Message details: srcId=" + nodeId + ", dstId=" + dstNodeId));
            sendToDevice(deviceAddress, meshMsg);
            seenMessageIds.add(messageId);
            mainHandler.post(() -> mainActivity.displayOutgoingMessage("[to " + deviceAddress + "] " + message));
        } else {
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Failed to encrypt message"));
        }
    }
    
    public void broadcastMessage(String message) {
        // For now, broadcast is the same as send to all connected devices
        // In a full mesh implementation, this would include routing logic
        sendMessage(message);
    }
    
    private void sendToDevice(String deviceAddress, String data) {
        ConnectionThread thread = connectionThreads.get(deviceAddress);
        if (thread != null) {
            thread.write(data.getBytes());
        }
    }
    
    public List<String> getConnectedDevices() {
        List<String> devices = new ArrayList<>();
        for (String address : connectedSockets.keySet()) {
            try {
                if (android.os.Build.VERSION.SDK_INT >= 31) {
                    if (context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        devices.add("Unknown (" + address + ")");
                        continue;
                    }
                }
                BluetoothDevice device = bluetoothAdapter.getRemoteDevice(address);
                String name = device.getName();
                devices.add((name != null ? name : "Unknown") + " (" + address + ")");
            } catch (SecurityException e) {
                devices.add("Unknown (" + address + ")");
            }
        }
        return devices;
    }
    
    // Get device address by friendly name (case-insensitive, partial match if unique)
    public String getConnectedDeviceAddressByName(String name) {
        if (name == null || name.trim().isEmpty()) return null;
        name = name.trim().toLowerCase();
        String foundAddress = null;
        int matchCount = 0;
        for (String address : connectedSockets.keySet()) {
            BluetoothDevice device = discoveredDevices.get(address);
            String devName = null;
            if (device != null && device.getName() != null) {
                devName = device.getName();
            } else {
                try {
                    BluetoothDevice remote = bluetoothAdapter.getRemoteDevice(address);
                    if (remote != null && remote.getName() != null) {
                        devName = remote.getName();
                    }
                } catch (Exception ignored) {}
            }
            if (devName != null) {
                String devNameLower = devName.trim().toLowerCase();
                if (devNameLower.equals(name)) {
                    return address; // exact match
                }
                if (devNameLower.contains(name)) {
                    foundAddress = address;
                    matchCount++;
                }
            }
        }
        // If only one partial match, return it
        if (matchCount == 1) return foundAddress;
        return null;
    }

    // Get list of connected device names for UI
    public List<String> getConnectedDevicesWithNames() {
        List<String> devices = new ArrayList<>();
        for (String address : connectedSockets.keySet()) {
            BluetoothDevice device = discoveredDevices.get(address);
            String name = null;
            if (device != null && device.getName() != null) {
                name = device.getName();
            } else {
                try {
                    BluetoothDevice remote = bluetoothAdapter.getRemoteDevice(address);
                    if (remote != null && remote.getName() != null) {
                        name = remote.getName();
                    }
                } catch (Exception ignored) {}
            }
            if (name == null) {
                // Show short address for easier identification
                String shortAddr = address.length() > 5 ? address.substring(address.length() - 5) : address;
                name = "Unknown-" + shortAddr;
            }
            devices.add(name + " (" + address + ")");
        }
        return devices;
    }
    
    public int getConnectedDevicesCount() {
        return connectedSockets.size();
    }
    
    // Get nodeId by device address
    public String getNodeIdByAddress(String address) {
        String nodeId = addressToNodeId.get(address);
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] getNodeIdByAddress(" + address + ") = " + nodeId));
        return nodeId;
    }

    // Find a nodeId by partial device name match
    public String findNodeIdByName(String partialName) {
        debugLog("[DEBUG] Looking for device with name containing: " + partialName);
        debugLog("[DEBUG] Current device names: " + knownDeviceNames.toString());
        
        String lowerPartialName = partialName.toLowerCase();
        
        for (Map.Entry<String, String> entry : knownDeviceNames.entrySet()) {
            String nodeId = entry.getKey();
            String deviceName = entry.getValue().toLowerCase();
            
            if (deviceName.contains(lowerPartialName)) {
                debugLog("[DEBUG] Found match: " + nodeId + " -> " + knownDeviceNames.get(nodeId));
                return nodeId;
            }
        }
        
        debugLog("[DEBUG] No device name found containing: " + partialName);
        return null;
    }        // Get device name by nodeId with fallback
    private String getDeviceNameByNodeId(String nodeId) {
        String name = knownDeviceNames.get(nodeId);
        if (name != null) {
            return name;
        }
        
        // Try to find a matching device address
        for (Map.Entry<String, String> entry : addressToNodeId.entrySet()) {
            if (nodeId.equals(entry.getValue())) {
                String address = entry.getKey();
                String deviceName = null;
                try {
                    BluetoothDevice device = bluetoothAdapter.getRemoteDevice(address);
                    if (device != null) {
                        deviceName = device.getName();
                    }
                } catch (Exception ignored) {}
                
                if (deviceName != null) {
                    debugLog("[DEBUG] Found name for nodeId " + nodeId + ": " + deviceName);
                    knownDeviceNames.put(nodeId, deviceName);
                    return deviceName;
                }
            }
        }
        
        debugLog("[DEBUG] No name found for nodeId: " + nodeId);
        return "Unknown-" + nodeId.substring(0, 5);
    }

    // BroadcastReceiver for discovering devices
    private final BroadcastReceiver discoveryReceiver = new BroadcastReceiver() {
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] BroadcastReceiver onReceive: action=" + action));
            if (BluetoothDevice.ACTION_FOUND.equals(action)) {
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                int rssi = intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, Short.MIN_VALUE);
                if (device != null) {
                    try {
                        if (android.os.Build.VERSION.SDK_INT >= 31) {
                            if (context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] BLUETOOTH_CONNECT permission not granted for found device"));
                                return;
                            }
                        }
                        String name = device.getName();
                        String address = device.getAddress();
                        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Device found: name=" + name + ", address=" + address + ", rssi=" + rssi));
                        // Filter for BLUBIT devices (you might want to implement a better identification method)
                        if (name != null && name.contains("BLUBIT")) {
                            discoveredDevices.put(address, device);
                            deviceRssiMap.put(address, rssi);
                            mainHandler.post(() -> mainActivity.displaySystemMessage("Found device: " + name + " (" + address + ") RSSI: " + rssi));
                        }
                    } catch (SecurityException e) {
                        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] SecurityException in ACTION_FOUND: " + e.getMessage()));
                    }
                } else {
                    mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] ACTION_FOUND: device is null"));
                }
            } else if (BluetoothAdapter.ACTION_DISCOVERY_FINISHED.equals(action)) {
                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Discovery finished. Found " + discoveredDevices.size() + " BLUBIT devices"));
            }
        }
    };
    
    // Thread for accepting incoming connections
    private class AcceptThread extends Thread {
        private BluetoothServerSocket serverSocket;
        
        public AcceptThread() {
            try {
                if (android.os.Build.VERSION.SDK_INT >= 31) {
                    if (context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("BLUETOOTH_CONNECT permission not granted for server socket"));
                        return;
                    }
                }
                serverSocket = bluetoothAdapter.listenUsingRfcommWithServiceRecord(SERVICE_NAME, SERVICE_UUID);
            } catch (IOException | SecurityException e) {
                Log.e(TAG, "Socket's listen() method failed", e);
            }
        }
        
        public void run() {
            BluetoothSocket socket = null;
            
            while (isRunning) {
                try {
                    socket = serverSocket.accept();
                } catch (IOException e) {
                    Log.e(TAG, "Socket's accept() method failed", e);
                    break;
                }
                
                if (socket != null) {
                    handleIncomingConnection(socket);
                }
            }
        }
        
        public void cancel() {
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                Log.e(TAG, "Could not close the server socket", e);
            }
        }
    }
    
    // Thread for connecting to a remote device
    private class ConnectThread extends Thread {
        private BluetoothSocket socket;
        private BluetoothDevice device;
        
        public ConnectThread(BluetoothDevice device) {
            this.device = device;
            try {
                if (android.os.Build.VERSION.SDK_INT >= 31) {
                    if (context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("BLUETOOTH_CONNECT permission not granted for client socket"));
                        return;
                    }
                }
                socket = device.createRfcommSocketToServiceRecord(SERVICE_UUID);
            } catch (IOException | SecurityException e) {
                Log.e(TAG, "Socket's create() method failed", e);
            }
        }
        
        public void run() {
            try {
                if (android.os.Build.VERSION.SDK_INT >= 31) {
                    if (context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_SCAN) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("BLUETOOTH_SCAN permission not granted for cancelDiscovery"));
                        return;
                    }
                }
                bluetoothAdapter.cancelDiscovery();
            } catch (SecurityException e) {
                mainActivity.runOnUiThread(() -> mainActivity.displaySystemMessage("cancelDiscovery failed: " + e.getMessage()));
                return;
            }
            try {
                socket.connect();
            } catch (IOException | SecurityException connectException) {
                try {
                    socket.close();
                } catch (IOException closeException) {
                    Log.e(TAG, "Could not close the client socket", closeException);
                }
                mainHandler.post(() -> mainActivity.displaySystemMessage("Failed to connect to " + device.getAddress() + ": " + connectException.getMessage()));
                return;
            }
            
            // Track this device as known for future reconnections
            knownDeviceAddresses.add(device.getAddress());
            
            // After successful connection, send nodeId handshake and handle the connection
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] ConnectThread: successful connection to " + device.getAddress()));
            handleIncomingConnection(socket);
        }
        
        public void cancel() {
            try {
                if (socket != null) socket.close();
            } catch (IOException e) {
                Log.e(TAG, "Could not close the connect socket", e);
            }
        }
    }
    
    private void handleIncomingConnection(BluetoothSocket socket) {
        String address = socket.getRemoteDevice().getAddress();
        ConnectionThread thread = new ConnectionThread(socket);
        connectionThreads.put(address, thread);
        connectedSockets.put(address, socket);
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] handleIncomingConnection: started thread for " + address));
        thread.start();
        
        // Track this device as known for future reconnections
        knownDeviceAddresses.add(address);
        
        // Send nodeId handshake immediately after connection
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Sending nodeId handshake to " + address + " after connection"));
        sendNodeIdToPeer(address);
        
        // Also initiate key exchange
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Initiating key exchange with " + address));
        sendPublicKeyToPeer(address);
    }
    
    // Send our nodeId to the peer after connection
    private void sendNodeIdToPeer(String deviceAddress) {
        String nodeIdMsg = "NODEID:" + nodeId;
        debugLog("[DEBUG] Sending nodeId to peer " + deviceAddress + ": " + nodeId);
        debugLog("[DEBUG] Current mappings: " + addressToNodeId.toString());
        sendToDevice(deviceAddress, nodeIdMsg);
    }
    
    // Send our public key to the peer
    private void sendPublicKeyToPeer(String deviceAddress) {
        PublicKey publicKey = cryptographyManager.getPublicKey();
        if (publicKey != null) {
            String publicKeyStr = cryptographyManager.getPublicKeyAsString(publicKey);
            if (publicKeyStr != null) {
                String keyMsg = "KEY:" + publicKeyStr;
                debugLog("[DEBUG] Sending public key to peer " + deviceAddress);
                sendToDevice(deviceAddress, keyMsg);
            } else {
                debugLog("[ERROR] Failed to get public key as string");
            }
        } else {
            debugLog("[ERROR] Failed to get public key for exchange");
        }
    }
    
    // Thread for managing a connection
    private class ConnectionThread extends Thread {
        private BluetoothSocket socket;
        private BluetoothDevice device;
        private InputStream inputStream;
        private OutputStream outputStream;
        private volatile boolean running = true;
        private String deviceAddress;
        
        public ConnectionThread(BluetoothSocket socket) {
            this.socket = socket;
            this.deviceAddress = socket.getRemoteDevice().getAddress();
            
            try {
                inputStream = socket.getInputStream();
                outputStream = socket.getOutputStream();
            } catch (IOException e) {
                Log.e(TAG, "Error occurred when creating input/output streams", e);
            }
        }
        
        public void run() {
            byte[] buffer = new byte[2048];
            int bytes;
            int reconnectAttempts = 0;
            while (isRunning) {
                try {
                    bytes = inputStream.read(buffer);
                    String receivedData = new String(buffer, 0, bytes);
                    // Mesh routing: parse and relay if needed
                    if (receivedData.startsWith("KEY:")) {
                        String publicKeyString = receivedData.substring(4);
                        PublicKey publicKey = cryptographyManager.getPublicKeyFromString(publicKeyString);
                        if (publicKey != null) {
                            devicePublicKeys.put(deviceAddress, publicKey);
                            mainHandler.post(() -> mainActivity.displaySystemMessage("Key exchange completed with " + deviceAddress));
                        }
                    } else if (receivedData.startsWith("MSG:")) {
                        String[] parts = receivedData.split(":", 5);
                        if (parts.length == 5) {
                            String msgId = parts[1];
                            String srcId = parts[2];
                            String dstId = parts[3];
                            String encrypted = parts[4];
                            // Always update mapping on every message
                            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Updating nodeId mapping from MSG: " + srcId + " -> " + deviceAddress));
                            updateNodeIdForAddress(deviceAddress, srcId);
                            if (!seenMessageIds.contains(msgId)) {
                                seenMessageIds.add(msgId);
                                // Debug message info
                                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Message received: msgId=" + msgId + ", srcId=" + srcId + ", dstId=" + dstId));
                                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] My nodeId=" + nodeId + ", should I display? " + (dstId.equals(nodeId) || dstId.equals("ALL"))));
                                
                                // If this node is the destination or broadcast
                                if (dstId.equals(nodeId) || dstId.equals("ALL")) {
                                    debugLog("[DEBUG] Attempting to decrypt message. Encrypted: " + encrypted);
                                    debugLog("[DEBUG] Using private key: " + cryptographyManager.getPublicKeyAsString(cryptographyManager.getPublicKey()));
                                    String decrypted = cryptographyManager.decryptMessage(encrypted);
                                    if (decrypted != null) {
                                        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Successfully decrypted message"));
                                        mainHandler.post(() -> mainActivity.displayIncomingMessage("From " + srcId + ": " + decrypted, deviceAddress));
                                    } else {
                                        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Failed to decrypt message. Encrypted: " + encrypted));
                                    }
                                } else {
                                    mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Message not for me, relaying"));
                                }
                            }
                        }
                    } else {
                        // Non-mesh messages (e.g., key exchange)
                        handleReceivedData(receivedData);
                    }
                } catch (IOException e) {
                    Log.d(TAG, "Input stream was disconnected", e);
                    // Auto-reconnect logic
                    if (reconnectAttempts < 3 && isRunning) {
                        reconnectAttempts++;
                        final int attemptNum = reconnectAttempts;
                        mainHandler.post(() -> mainActivity.displaySystemMessage("Connection lost with " + deviceAddress + ". Attempting to reconnect (" + attemptNum + "/3)..."));
                        try {
                            Thread.sleep(2000); // Wait 2 seconds before reconnect
                        } catch (InterruptedException ie) {
                            // Ignore
                        }
                        // Try to reconnect
                        BluetoothDevice device = bluetoothAdapter.getRemoteDevice(deviceAddress);
                        if (device != null) {
                            ConnectThread reconnectThread = new ConnectThread(device);
                            reconnectThread.start();
                        }
                    } else {
                        mainHandler.post(() -> mainActivity.displaySystemMessage("Failed to reconnect to " + deviceAddress));
                        // Try reconnecting to all known devices
                        for (String addr : knownDeviceAddresses) {
                            if (!connectedSockets.containsKey(addr)) {
                                BluetoothDevice dev = bluetoothAdapter.getRemoteDevice(addr);
                                if (dev != null) {
                                    mainHandler.post(() -> mainActivity.displaySystemMessage("Attempting to reconnect to known device: " + addr));
                                    ConnectThread reconnectThread = new ConnectThread(dev);
                                    reconnectThread.start();
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
        
        private void handleReceivedData(String data) {
            if (data.startsWith("NODEID:")) {
                String peerNodeId = data.substring(7);
                Log.d(TAG, "[LOGCAT] Received NODEID from " + deviceAddress + ": " + peerNodeId);
                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Received NODEID from " + deviceAddress + ": " + peerNodeId));
                updateNodeIdForAddress(deviceAddress, peerNodeId);
                mainHandler.post(() -> mainActivity.displaySystemMessage("Node ID received from " + deviceAddress + ": " + peerNodeId));
            } else if (data.startsWith("KEY:")) {
                String publicKeyString = data.substring(4);
                PublicKey publicKey = cryptographyManager.getPublicKeyFromString(publicKeyString);
                String stableAddress = deviceAddress.trim().toUpperCase();
                StringBuilder keysDump = new StringBuilder();
                for (String addr : devicePublicKeys.keySet()) {
                    keysDump.append(addr).append(": ").append(cryptographyManager.getPublicKeyAsString(devicePublicKeys.get(addr))).append("\n");
                }
                Log.d(TAG, "[LOGCAT] deviceAddress=" + stableAddress + ", devicePublicKeys=\n" + keysDump);
                if (publicKey != null) {
                    if (!devicePublicKeys.containsKey(stableAddress)) {
                        devicePublicKeys.put(stableAddress, publicKey);
                        Log.d(TAG, "[LOGCAT] Key exchange completed with " + stableAddress + ". devicePublicKeys now=\n" + keysDump);
                        mainHandler.post(() -> mainActivity.displaySystemMessage("Key exchange completed with " + stableAddress));
                    } else {
                        Log.d(TAG, "[LOGCAT] Key already exchanged with " + stableAddress + ", ignoring duplicate key. devicePublicKeys=\n" + keysDump);
                        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Key already exchanged with " + stableAddress));
                    }
                } else {
                    Log.d(TAG, "[LOGCAT] Received invalid public key from " + stableAddress);
                }
            } else if (data.startsWith("MSG:")) {
                Log.d(TAG, "[LOGCAT] Received MSG: " + data);
                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Received MSG: " + data));
            }
        }

        public void cancel() {
            running = false;
            try {
                if (socket != null) socket.close();
            } catch (IOException e) {
                Log.e(TAG, "Could not close the connect socket", e);
            }
        }
        public void write(byte[] bytes) {
            try {
                if (outputStream != null) outputStream.write(bytes);
            } catch (IOException e) {
                Log.e(TAG, "Error occurred when sending data", e);
            }
        }
    }

    public void onMessageReceived(String deviceAddress, String message) {
        // Handle nodeId handshake messages
        if (message.startsWith("NODEID:")) {
            String peerNodeId = message.substring(7);
            debugLog("[DEBUG] Received nodeId handshake from " + deviceAddress + ": " + peerNodeId);
            updateNodeIdForAddress(deviceAddress, peerNodeId);
            return;
        }

        try {
            JSONObject messageObject = new JSONObject(message);
            String senderId = messageObject.getString("senderId");
            String originalSenderId = messageObject.getString("originalSenderId");
            String content = messageObject.getString("content");
            int hopCount = messageObject.getInt("hopCount");
            String targetNodeId = messageObject.optString("targetNodeId", null);
            
            debugLog("[DEBUG] Message received from " + deviceAddress + 
                " (senderId: " + senderId + ", originalSender: " + originalSenderId + 
                ", hops: " + hopCount + ", targetNodeId: " + targetNodeId + ")");

            // Filter: Check if I'm the target (if message has a target)
            if (targetNodeId != null && !targetNodeId.isEmpty() && !targetNodeId.equals(nodeId)) {
                debugLog("[DEBUG] Message filtered: not for me, targeted to " + targetNodeId);
                
                // Forward message to other connected devices if hop count allows
                if (hopCount < MAX_HOP_COUNT) {
                    debugLog("[DEBUG] Forwarding targeted message to other devices");
                    forwardMessage(message, deviceAddress);
                }
                return;
            }

            // Don't display if it's from ourselves (forwarded back to us)
            if (originalSenderId.equals(nodeId)) {
                debugLog("[DEBUG] Message filtered: it's from ourselves (originalSenderId: " + originalSenderId + ")");
                return;
            }
            
            // Display the message in the UI
            String displayName = getDeviceNameByNodeId(originalSenderId);
            mainHandler.post(() -> mainActivity.displayIncomingMessage(displayName + ": " + content, deviceAddress));
            
            // Forward message to other connected devices if hop count allows
            if (hopCount < MAX_HOP_COUNT) {
                forwardMessage(message, deviceAddress);
            } else {
                debugLog("[DEBUG] Not forwarding: max hop count reached (" + hopCount + ")");
            }
        } catch (JSONException e) {
            Log.e(TAG, "Error parsing message: " + e.getMessage());
            mainHandler.post(() -> mainActivity.displaySystemMessage("[ERROR] Failed to parse message: " + e.getMessage()));
        }
    }

    private void forwardMessage(String message, String sourceDeviceAddress) {
        // Forward message to all connected devices except the source
        debugLog("[DEBUG] Forwarding message to connected devices (excluding " + sourceDeviceAddress + ")");
        
        Set<String> connectedAddresses = new HashSet<>(connectedSockets.keySet());
        connectedAddresses.remove(sourceDeviceAddress);
        
        if (connectedAddresses.isEmpty()) {
            debugLog("[DEBUG] No other devices to forward to");
            return;
        }
        
        for (String deviceAddress : connectedAddresses) {
            try {
                JSONObject messageObj = new JSONObject(message);
                int currentHopCount = messageObj.getInt("hopCount");
                messageObj.put("hopCount", currentHopCount + 1);
                messageObj.put("senderId", nodeId);
                
                String targetNodeId = messageObj.optString("targetNodeId", null);
                String deviceNodeId = addressToNodeId.get(deviceAddress);
                
                if (targetNodeId != null && !targetNodeId.isEmpty()) {
                    if (targetNodeId.equals(deviceNodeId)) {
                        debugLog("[DEBUG] Found target node! Forwarding directly to " + 
                            deviceAddress + " (nodeId: " + deviceNodeId + ")");
                    } else {
                        debugLog("[DEBUG] Forwarding targeted message to " + 
                            deviceAddress + " (nodeId: " + (deviceNodeId != null ? deviceNodeId : "unknown") + ")");
                    }
                } else {
                    debugLog("[DEBUG] Forwarding broadcast message to " + 
                        deviceAddress + " (nodeId: " + (deviceNodeId != null ? deviceNodeId : "unknown") + ")");
                }
                
                sendToDevice(deviceAddress, messageObj.toString());
            } catch (JSONException e) {
                Log.e(TAG, "Error forwarding message: " + e.getMessage());
                mainHandler.post(() -> mainActivity.displaySystemMessage("[ERROR] Failed to forward message: " + e.getMessage()));
            }
        }
    }

    public void sendMessage(String message, String targetNodeId) {
        Set<String> connectedDevices = connectedSockets.keySet();
        if (connectedDevices.isEmpty()) {
            debugLog("[DEBUG] No connected devices to send message to");
            return;
        }

        try {
            JSONObject messageObject = new JSONObject();
            messageObject.put("originalSenderId", nodeId);
            messageObject.put("senderId", nodeId);
            messageObject.put("content", message);
            messageObject.put("hopCount", 1);
            
            if (targetNodeId != null && !targetNodeId.isEmpty()) {
                messageObject.put("targetNodeId", targetNodeId);
                debugLog("[DEBUG] Sending targeted message to nodeId: " + targetNodeId);
                
                // Check if we have a direct connection to the target
                String targetDeviceAddress = null;
                for (Map.Entry<String, String> entry : addressToNodeId.entrySet()) {
                    if (targetNodeId.equals(entry.getValue())) {
                        targetDeviceAddress = entry.getKey();
                        break;
                    }
                }
                
                if (targetDeviceAddress != null && connectedDevices.contains(targetDeviceAddress)) {
                    debugLog("[DEBUG] Found direct connection to target! Sending directly to " + 
                        targetDeviceAddress + " (nodeId: " + targetNodeId + ")");
                    sendToDevice(targetDeviceAddress, messageObject.toString());
                    return;
                } else {
                    debugLog("[DEBUG] No direct connection to target " + targetNodeId + 
                        ", will send through mesh network");
                }
            } else {
                debugLog("[DEBUG] Sending broadcast message to all nodes");
            }

            String messageString = messageObject.toString();
            
            // Find the best device to route through (highest RSSI)
            String bestDevice = null;
            int bestRssi = Integer.MIN_VALUE;
            
            for (String deviceAddress : connectedDevices) {
                Integer rssi = deviceRssiMap.get(deviceAddress);
                if (rssi != null) {
                    debugLog("[DEBUG] Device " + deviceAddress + 
                        " (nodeId: " + (addressToNodeId.get(deviceAddress) != null ? addressToNodeId.get(deviceAddress) : "unknown") + 
                        ") has RSSI: " + deviceRssiMap.get(deviceAddress));
                        
                    if (rssi > bestRssi) {
                        bestRssi = rssi;
                        bestDevice = deviceAddress;
                    }
                } else {
                    debugLog("[DEBUG] Device " + deviceAddress + 
                        " (nodeId: " + (addressToNodeId.get(deviceAddress) != null ? addressToNodeId.get(deviceAddress) : "unknown") + 
                        ") has unknown RSSI");
                }
            }
            
            // If we found a best device, send to it, otherwise send to all
            if (bestDevice != null) {
                debugLog("[DEBUG] Selected best route: " + bestDevice + 
                    " (nodeId: " + (addressToNodeId.get(bestDevice) != null ? addressToNodeId.get(bestDevice) : "unknown") + 
                    ") with RSSI: " + bestRssi);
                sendToDevice(bestDevice, messageString);
            } else {
                debugLog("[DEBUG] No RSSI data available, sending to all connected devices");
                for (String deviceAddress : connectedDevices) {
                    sendToDevice(deviceAddress, messageString);
                }
            }

        } catch (JSONException e) {
            Log.e(TAG, "Error creating message: " + e.getMessage());
            mainHandler.post(() -> mainActivity.displaySystemMessage("[ERROR] Failed to create message: " + e.getMessage()));
        }
    }

    // Update the RSSI value for a device
    public void updateDeviceRssi(String deviceAddress, int rssi) {
        int oldRssi = deviceRssiMap.getOrDefault(deviceAddress, Integer.MIN_VALUE);
        deviceRssiMap.put(deviceAddress, rssi);
        
        // Only log if the RSSI changed significantly (by 5 or more)
        if (Math.abs(rssi - oldRssi) >= 5 || oldRssi == Integer.MIN_VALUE) {
            String nodeId = addressToNodeId.get(deviceAddress);
            String deviceInfo = deviceAddress;
            if (nodeId != null) {
                String name = knownDeviceNames.get(nodeId);
                deviceInfo += " (" + (name != null ? name : "nodeId: " + nodeId) + ")";
            }
            debugLog("[DEBUG] Updated RSSI for " + deviceInfo + ": " + rssi);
        }
    }

    private boolean debugEnabled = true;
    
    // Toggle debug mode
    public boolean toggleDebugMode() {
        debugEnabled = !debugEnabled;
        return debugEnabled;
    }
    
    // Display debug message if debug is enabled
    private void debugLog(String message) {
        if (debugEnabled) {
            mainHandler.post(() -> mainActivity.displaySystemMessage(message));
        }
    }
    
    /**
     * Check if we have public keys for all connected devices
     */
    public void verifyPublicKeys() {
        debugLog("[DEBUG] Checking public keys for all connected devices...");
        for (String address : connectedSockets.keySet()) {
            if (!devicePublicKeys.containsKey(address)) {
                debugLog("[DEBUG] Missing public key for " + address + ", sending key exchange request");
                sendPublicKeyToPeer(address);
            }
        }
        debugLog("[DEBUG] Public key verification complete");
    }
    
    // Get status information about node mappings
    public String getNodeMappingStatus() {
        StringBuilder status = new StringBuilder();
        status.append("This device nodeId: ").append(nodeId).append("\n");
        
        if (addressToNodeId.isEmpty()) {
            status.append("No known node mappings");
        } else {
            status.append("Address to NodeId mappings:\n");
            for (Map.Entry<String, String> entry : addressToNodeId.entrySet()) {
                String address = entry.getKey();
                String nodeId = entry.getValue();
                String name = knownDeviceNames.get(nodeId);
                String rssiInfo = deviceRssiMap.containsKey(address) ? 
                    ", RSSI: " + deviceRssiMap.get(address) : "";
                
                status.append("- ").append(address)
                      .append(" -> ").append(nodeId)
                      .append(name != null ? " (" + name + ")" : "")
                      .append(rssiInfo)
                      .append("\n");
            }
        }
        
        return status.toString();
    }
}