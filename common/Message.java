package common;

import java.io.Serializable;

/** One application message. Payload type depends on the message type. */
public class Message implements Serializable {
    private static final long serialVersionUID = 1L;

    private final MessageType type;
    private final String senderId;
    private final String targetId;
    private final Object payload;
    private final byte[] iv;

    public Message(MessageType type, Object payload) {
        this(type, null, null, payload, null);
    }

    public Message(MessageType type, String senderId, String targetId, Object payload, byte[] iv) {
        this.type = type;
        this.senderId = senderId;
        this.targetId = targetId;
        this.payload = payload;
        this.iv = iv == null ? null : iv.clone();
    }

    public MessageType type() { return type; }
    public String senderId() { return senderId; }
    public String targetId() { return targetId; }
    public Object payload() { return payload; }
    public byte[] iv() { return iv == null ? null : iv.clone(); }
}
