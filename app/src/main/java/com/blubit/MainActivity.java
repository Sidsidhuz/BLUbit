package com.blubit;

import android.Manifest;
import com.blubit.MeshNetworkManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private ActivityResultLauncher<Intent> enableBluetoothLauncher;
    private static final int REQUEST_ENABLE_BT = 1;
    private static final int REQUEST_PERMISSIONS = 2;
    
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothManager bluetoothManager;
    private MeshNetworkManager meshNetworkManager;
    private CryptographyManager cryptographyManager;
    
    private RecyclerView terminalRecyclerView;
    private TerminalAdapter terminalAdapter;
    private List<TerminalMessage> messages;
    private EditText commandInput;
    private Button sendButton;
    private TextView statusText;
    
    private boolean isBluetoothEnabled = false;
    private boolean isDiscoverable = false;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        enableBluetoothLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == RESULT_OK) {
                    isBluetoothEnabled = true;
                    startMeshNetwork();
                } else {
                    Toast.makeText(this, "Bluetooth is required for BLUBIT to work", Toast.LENGTH_LONG).show();
                }
            }
        );

        initializeViews();
        initializeBluetooth();
        initializeManagers();
        setupTerminal();
        checkPermissions();

        displayWelcomeMessage();
    }
    
    private void initializeViews() {
        terminalRecyclerView = findViewById(R.id.terminal_recycler_view);
        commandInput = findViewById(R.id.command_input);
        sendButton = findViewById(R.id.send_button);
        statusText = findViewById(R.id.status_text);
        
        sendButton.setOnClickListener(v -> processCommand());
        commandInput.setOnEditorActionListener((v, actionId, event) -> {
            processCommand();
            return true;
        });
    }
    
    private void initializeBluetooth() {
        bluetoothManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        bluetoothAdapter = bluetoothManager.getAdapter();

        if (bluetoothAdapter == null) {
            Toast.makeText(this, "Bluetooth is not supported on this device", Toast.LENGTH_LONG).show();
            finish();
            return;
        }

        // Set Bluetooth device name to BLUBIT-XXXX for easier discovery
        if (android.os.Build.VERSION.SDK_INT < 31 ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
            String address = bluetoothAdapter.getAddress();
            if (address != null && !bluetoothAdapter.getName().startsWith("BLUBIT")) {
                String suffix = address.replace(":", "");
                if (suffix.length() >= 4) {
                    suffix = suffix.substring(suffix.length() - 4);
                }
                String newName = "BLUBIT-" + suffix;
                bluetoothAdapter.setName(newName);
            }
        }
    }
    
    private void initializeManagers() {
        cryptographyManager = new CryptographyManager();
        meshNetworkManager = new MeshNetworkManager(this, bluetoothAdapter, cryptographyManager);
    }
    
    private void setupTerminal() {
        messages = new ArrayList<>();
        terminalAdapter = new TerminalAdapter(messages);
        terminalRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        terminalRecyclerView.setAdapter(terminalAdapter);
    }
    
    private void checkPermissions() {
        List<String> permissionsToRequest = new ArrayList<>();
        // Always request location permissions for Bluetooth scanning
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissionsToRequest.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissionsToRequest.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        }

        // On Android 12+ (API 31+), request Bluetooth permissions at runtime
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.BLUETOOTH_SCAN);
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.BLUETOOTH_CONNECT);
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.BLUETOOTH_ADVERTISE);
            }
        }

        if (!permissionsToRequest.isEmpty()) {
            ActivityCompat.requestPermissions(this,
                    permissionsToRequest.toArray(new String[0]),
                    REQUEST_PERMISSIONS);
        } else {
            enableBluetooth();
        }
    }
    
    private void enableBluetooth() {
        if (!bluetoothAdapter.isEnabled()) {
            Intent enableBtIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            enableBluetoothLauncher.launch(enableBtIntent);
        } else {
            isBluetoothEnabled = true;
            startMeshNetwork();
        }
    }
    
    private void startMeshNetwork() {
        updateStatus("Starting BLUBIT mesh network...");
        meshNetworkManager.startMeshNetwork();
        displaySystemMessage("BLUBIT mesh network started");
        displaySystemMessage("Type 'help' for available commands");
    }
    
    private void displayWelcomeMessage() {
        displaySystemMessage("=== BLUBIT Terminal ===");
        displaySystemMessage("Bluetooth Mesh Messaging System");
        displaySystemMessage("End-to-End Encrypted Communication");
        displaySystemMessage("Initializing...");
    }
    
    private void processCommand() {
        String command = commandInput.getText().toString().trim();
        if (command.isEmpty()) return;
        
        commandInput.setText("");
        displayUserCommand(command);
        
        String[] parts = command.split(" ", 2);
        String cmd = parts[0].toLowerCase();
        
        switch (cmd) {
            case "mkdisc":
                meshNetworkManager.makeDiscoverable();
                break;
            case "help":
                displayHelp();
                break;
            case "status":
                displayStatus();
                break;
            case "scan":
                scanForDevices();
                break;
            case "connect":
                if (parts.length > 1) {
                    connectToDevice(parts[1]);
                } else {
                    displaySystemMessage("Usage: connect <device_address>");
                }
                break;
            case "disconnect":
                if (parts.length > 1) {
                    disconnectFromDevice(parts[1]);
                } else {
                    displaySystemMessage("Usage: disconnect <device_address>");
                }
                break;
            case "msg":
                if (parts.length > 1) {
                    sendMessage(parts[1]);
                } else {
                    displaySystemMessage("Usage: msg <message>");
                }
                break;
            case "broadcast":
                if (parts.length > 1) {
                    broadcastMessage(parts[1]);
                } else {
                    displaySystemMessage("Usage: broadcast <message>");
                }
                break;
            case "nodes":
                listConnectedNodes();
                break;
            case "clear":
                clearTerminal();
                break;
            case "exit":
                finish();
                break;
            default:
                displaySystemMessage("Unknown command: " + cmd + ". Type 'help' for available commands.");
        }
    }
    
    private void displayHelp() {
        displaySystemMessage("Available commands:");
        displaySystemMessage("  help        - Show this help message");
        displaySystemMessage("  status      - Show network status");
        displaySystemMessage("  scan        - Scan for nearby devices");
        displaySystemMessage("  connect <addr> - Connect to device");
        displaySystemMessage("  disconnect <addr> - Disconnect from device");
        displaySystemMessage("  msg <text>  - Send message to connected devices");
        displaySystemMessage("  broadcast <text> - Broadcast message to all nodes");
        displaySystemMessage("  nodes       - List connected nodes");
        displaySystemMessage("  clear       - Clear terminal");
        displaySystemMessage("  exit        - Exit application");
    }
    
    private void displayStatus() {
        displaySystemMessage("=== BLUBIT Status ===");
        displaySystemMessage("Bluetooth: " + (isBluetoothEnabled ? "Enabled" : "Disabled"));
        displaySystemMessage("Discoverable: " + (isDiscoverable ? "Yes" : "No"));
        displaySystemMessage("Connected nodes: " + meshNetworkManager.getConnectedDevicesCount());
        displaySystemMessage("Encryption: AES-256 + RSA");
    }
    
    private void scanForDevices() {
        displaySystemMessage("Scanning for nearby BLUBIT devices...");
        meshNetworkManager.startDiscovery();
    }
    
    private void connectToDevice(String address) {
        displaySystemMessage("Connecting to device: " + address);
        meshNetworkManager.connectToDevice(address);
    }
    
    private void disconnectFromDevice(String address) {
        displaySystemMessage("Disconnecting from device: " + address);
        meshNetworkManager.disconnectFromDevice(address);
    }
    
    private void sendMessage(String message) {
        displaySystemMessage("Sending message: " + message);
        meshNetworkManager.sendMessage(message);
    }
    
    private void broadcastMessage(String message) {
        displaySystemMessage("Broadcasting message: " + message);
        meshNetworkManager.broadcastMessage(message);
    }
    
    private void listConnectedNodes() {
        List<String> connectedDevices = meshNetworkManager.getConnectedDevices();
        if (connectedDevices.isEmpty()) {
            displaySystemMessage("No connected nodes");
        } else {
            displaySystemMessage("Connected nodes:");
            for (String device : connectedDevices) {
                displaySystemMessage("  " + device);
            }
        }
    }
    
    private void clearTerminal() {
        messages.clear();
        terminalAdapter.notifyDataSetChanged();
    }
    
    private void displayUserCommand(String command) {
        addMessage(new TerminalMessage("> " + command, TerminalMessage.Type.USER_INPUT));
    }
    
    public void displaySystemMessage(String message) {
        addMessage(new TerminalMessage(message, TerminalMessage.Type.SYSTEM));
    }
    
    public void displayIncomingMessage(String message, String sender) {
        addMessage(new TerminalMessage("[" + sender + "] " + message, TerminalMessage.Type.INCOMING));
    }
    
    public void displayOutgoingMessage(String message) {
        addMessage(new TerminalMessage("[SENT] " + message, TerminalMessage.Type.OUTGOING));
    }
    
    private void addMessage(TerminalMessage message) {
        messages.add(message);
        terminalAdapter.notifyItemInserted(messages.size() - 1);
        terminalRecyclerView.scrollToPosition(messages.size() - 1);
    }
    
    private void updateStatus(String status) {
        statusText.setText(status);
    }
    
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_PERMISSIONS) {
            boolean allGranted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            
            if (allGranted) {
                enableBluetooth();
            } else {
                Toast.makeText(this, "Bluetooth permissions are required for BLUBIT to work", Toast.LENGTH_LONG).show();
            }
        }
    }
    

    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (meshNetworkManager != null) {
            meshNetworkManager.stopMeshNetwork();
        }
    }
}