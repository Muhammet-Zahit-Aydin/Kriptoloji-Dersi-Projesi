// src/common/Message.java
package common ;

import java.io.Serializable ;

// TCP üzerinden bytelara dönüştürüp gönderir
public record Message(MessageType type, Object payload) implements Serializable {}