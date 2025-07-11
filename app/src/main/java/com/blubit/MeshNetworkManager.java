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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class MeshNetworkManager {
    private static final String TAG = "MeshNetworkManager";
    private static final String SERVICE_NAME = "BLUBIT_MESH";
    private static final UUID SERVICE_UUID = UUID.fromString("12345678-1234-5678-9012-123456789abc");
    private static final int DISCOVERY_DURATION = 0; // 0 means forever (system maximum)
    
    private Context context;
    private BluetoothAdapter bluetoothAdapter;
    private CryptographyManager cryptographyManager;
    private MainActivity mainActivity;
    
    private BluetoothServerSocket serverSocket;
    private Map<String, BluetoothDevice> discoveredDevices;
    private Map<String, BluetoothSocket> connectedSockets;
    private Map<String, PublicKey> devicePublicKeys;
    private Map<String, ConnectionThread> connectionThreads;
    
    private AcceptThread acceptThread;
    private Handler mainHandler;
    private boolean isRunning = false;
    
    public MeshNetworkManager(MainActivity activity, BluetoothAdapter adapter, CryptographyManager cryptoManager) {
        this.context = activity;
        this.mainActivity = activity;
        this.bluetoothAdapter = adapter;
        this.cryptographyManager = cryptoManager;
        this.discoveredDevices = new ConcurrentHashMap<>();
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
        discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, DISCOVERY_DURATION); // 0 means forever, but most Android devices limit to 300 seconds (5 minutes)
        mainActivity.startActivity(discoverableIntent);
        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Requested device to become discoverable again."));
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
            devicePublicKeys.remove(deviceAddress);
        }
    }
    
    public void sendMessage(String message) {
        if (connectedSockets.isEmpty()) {
            mainHandler.post(() -> mainActivity.displaySystemMessage("No connected devices"));
            return;
        }
        
        for (Map.Entry<String, BluetoothSocket> entry : connectedSockets.entrySet()) {
            String deviceAddress = entry.getKey();
            PublicKey publicKey = devicePublicKeys.get(deviceAddress);
            
            if (publicKey != null) {
                String encryptedMessage = cryptographyManager.encryptMessage(message, publicKey);
                if (encryptedMessage != null) {
                    sendToDevice(deviceAddress, "MSG:" + encryptedMessage);
                }
            }
        }
        
        mainHandler.post(() -> mainActivity.displayOutgoingMessage(message));
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
    
    public int getConnectedDevicesCount() {
        return connectedSockets.size();
    }
    
    // BroadcastReceiver for discovering devices
    private final BroadcastReceiver discoveryReceiver = new BroadcastReceiver() {
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] BroadcastReceiver onReceive: action=" + action));
            if (BluetoothDevice.ACTION_FOUND.equals(action)) {
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
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
                        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Device found: name=" + name + ", address=" + address));
                        // Add all discovered devices
                        discoveredDevices.put(address, device);
                        mainHandler.post(() -> mainActivity.displaySystemMessage("Found device: " + (name != null ? name : "Unknown") + " (" + address + ")"));
                    } catch (SecurityException e) {
                        mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] SecurityException in ACTION_FOUND: " + e.getMessage()));
                    }
                } else {
                    mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] ACTION_FOUND: device is null"));
                }
            } else if (BluetoothAdapter.ACTION_DISCOVERY_FINISHED.equals(action)) {
                mainHandler.post(() -> mainActivity.displaySystemMessage("[DEBUG] Discovery finished. Found " + discoveredDevices.size() + " devices"));
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
            
            handleIncomingConnection(socket);
        }
        
        public void cancel() {
            try {
                socket.close();
            } catch (IOException e) {
                Log.e(TAG, "Could not close the client socket", e);
            }
        }
    }
    
    private void handleIncomingConnection(BluetoothSocket socket) {
        String deviceAddress = socket.getRemoteDevice().getAddress();
        connectedSockets.put(deviceAddress, socket);
        
        ConnectionThread connectionThread = new ConnectionThread(socket);
        connectionThreads.put(deviceAddress, connectionThread);
        connectionThread.start();
        
        // Exchange public keys
        String publicKeyString = cryptographyManager.getPublicKeyString();
        if (publicKeyString != null) {
            connectionThread.write(("KEY:" + publicKeyString).getBytes());
        }
        
        mainHandler.post(() -> mainActivity.displaySystemMessage("Connected to " + deviceAddress));
    }
    
    // Thread for managing a connection
    private class ConnectionThread extends Thread {
        private BluetoothSocket socket;
        private InputStream inputStream;
        private OutputStream outputStream;
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
            byte[] buffer = new byte[1024];
            int bytes;
            
            while (isRunning) {
                try {
                    bytes = inputStream.read(buffer);
                    String receivedData = new String(buffer, 0, bytes);
                    handleReceivedData(receivedData);
                } catch (IOException e) {
                    Log.d(TAG, "Input stream was disconnected", e);
                    break;
                }
            }
        }
        
        private void handleReceivedData(String data) {
            if (data.startsWith("KEY:")) {
                String publicKeyString = data.substring(4);
                PublicKey publicKey = cryptographyManager.getPublicKeyFromString(publicKeyString);
                if (publicKey != null) {
                    devicePublicKeys.put(deviceAddress, publicKey);
                    mainHandler.post(() -> mainActivity.displaySystemMessage("Key exchange completed with " + deviceAddress));
                }
            } else if (data.startsWith("MSG:")) {
                String encryptedMessage = data.substring(4);
                String decryptedMessage = cryptographyManager.decryptMessage(encryptedMessage);
                if (decryptedMessage != null) {
                    mainHandler.post(() -> mainActivity.displayIncomingMessage(decryptedMessage, deviceAddress));
                }
            }
        }
        
        public void write(byte[] bytes) {
            try {
                outputStream.write(bytes);
            } catch (IOException e) {
                Log.e(TAG, "Error occurred when sending data", e);
            }
        }
        
        public void cancel() {
            try {
                socket.close();
            } catch (IOException e) {
                Log.e(TAG, "Could not close the connect socket", e);
            }
        }
    }
}
