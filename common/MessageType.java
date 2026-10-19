// src/common/MessageType.java
package common ;

public enum MessageType {

    REGISTER ,
    TEXT ,
    FILE_START ,
    FILE_CHUNK ,
    FILE_END ,
    KEY_EXCHANGE ,
    ACK ,
    ERROR ,
    KEY_EXCHANGE_INIT ,
    KEY_EXCHANGE_REPLY ,
    DATA_TRANSFER ,
    DISCONNECT

}