package com.blubit;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;

public class TerminalAdapter extends RecyclerView.Adapter<TerminalAdapter.MessageViewHolder> {
    private List<TerminalMessage> messages;

    public TerminalAdapter(List<TerminalMessage> messages) {
        this.messages = messages;
    }

    @NonNull
    @Override
    public MessageViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_terminal_message, parent, false);
        return new MessageViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull MessageViewHolder holder, int position) {
        TerminalMessage message = messages.get(position);
        holder.bind(message);
    }

    @Override
    public int getItemCount() {
        return messages.size();
    }

    static class MessageViewHolder extends RecyclerView.ViewHolder {
        private TextView messageText;
        private TextView timestampText;

        public MessageViewHolder(@NonNull View itemView) {
            super(itemView);
            messageText = itemView.findViewById(R.id.message_text);
            timestampText = itemView.findViewById(R.id.timestamp_text);
        }

        public void bind(TerminalMessage message) {
            messageText.setText(message.getMessage());
            timestampText.setText(message.getFormattedTimestamp());

            // Set color based on message type
            switch (message.getType()) {
                case SYSTEM:
                    messageText.setTextColor(Color.parseColor("#00FF00")); // Green
                    break;
                case USER_INPUT:
                    messageText.setTextColor(Color.parseColor("#FFFFFF")); // White
                    break;
                case INCOMING:
                    messageText.setTextColor(Color.parseColor("#00FFFF")); // Cyan
                    break;
                case OUTGOING:
                    messageText.setTextColor(Color.parseColor("#FFFF00")); // Yellow
                    break;
                case ERROR:
                    messageText.setTextColor(Color.parseColor("#FF0000")); // Red
                    break;
                default:
                    messageText.setTextColor(Color.parseColor("#FFFFFF")); // White
            }
        }
    }
}
