// src/common/Message.java
package common ;

import java.io.Serializable ;

// TCP üzerinden bytelara dönüştürüp gönderir
public record Message(MessageType type , String senderId , String targetId , Object payload , byte[] iv) implements Serializable {

    // Client2'nin kullandığı eski yapı
    public Message(MessageType type , Object payload) {

        this(type , null , null , payload , null) ;

    }

}