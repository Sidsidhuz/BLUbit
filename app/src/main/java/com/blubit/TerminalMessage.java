package com.blubit;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class TerminalMessage {
    public enum Type {
        SYSTEM,
        USER_INPUT,
        INCOMING,
        OUTGOING,
        ERROR
    }
    
    private String message;
    private Type type;
    private long timestamp;
    
    public TerminalMessage(String message, Type type) {
        this.message = message;
        this.type = type;
        this.timestamp = System.currentTimeMillis();
    }
    
    public String getMessage() {
        return message;
    }
    
    public Type getType() {
        return type;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public String getFormattedTimestamp() {
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
        return sdf.format(new Date(timestamp));
    }
}