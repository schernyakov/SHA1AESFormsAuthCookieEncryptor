"use strict";

const crypto = require("crypto");
const BufferWriter = require("./buffer-writer");

module.exports = (vk, dk) => {

    if (!vk || !dk)
        throw new Error("Validation key or decryption key was not set!");

    const validationKey = new Buffer(vk, 'hex');
    const decryptionKey = new Buffer(dk, 'hex');
    const headerSize = 32;

    function createCypher() {
        // IV size = 16
        return crypto.createCipheriv('aes-256-cbc', decryptionKey, Buffer.alloc(16));
    }

    function createDefaultTicket() {
        return {
            ticketVersion: 2,
            issueDate: new Date(),
            expirationDate: null,
            isPersistent: false,
            name: null,
            customData: '',
            cookiePath: '/'
        };
    }

    function validateTicket(ticket) {
        if (!ticket.expirationDate)
            throw new Error("expiration date was not set!");
        if (!ticket.name)
            throw new Error("name was not set!");
    }

    function encrypt(targetTicket) {
        var ticket = createDefaultTicket();
        Object.assign(ticket, targetTicket);
        validateTicket(ticket);


        var headerWriter = new BufferWriter(headerSize);
        headerWriter.writeBuffer(crypto.randomBytes(headerSize));
        var headerBuffer = headerWriter.buffer;
        /*serializationVersion : 1,
        ticketVersion :1,
        issueDate : 8,
        spacer: 1,
        expirationDate: 8,
        isPersistent: 1,
        footer: 1*/
        const fieldsSize = 21;

        var stringsSize = BufferWriter.stringSize(ticket.name) + BufferWriter.stringSize(ticket.customData) + BufferWriter.stringSize(ticket.cookiePath);

        var ticketSize = fieldsSize + stringsSize;
        var ticketWriter = new BufferWriter(ticketSize);

        // ticket serialization version 
        ticketWriter.writeByte(1)
        // ticket version
        ticketWriter.writeByte(ticket.ticketVersion);
        // issue date
        ticketWriter.writeDate(ticket.issueDate)
        if (ticketWriter.offset != 10)
            throw new Error("Critical to be on position 10 at this point.")
        // spacer
        ticketWriter.writeByte(0xfe)
        // expiration date
        ticketWriter.writeDate(ticket.expirationDate);
        // persistance
        ticketWriter.writeBool(ticket.isPersistent);
        // name
        ticketWriter.writeString(ticket.name);
        // user data
        ticketWriter.writeString(ticket.customData);
        // cookie path
        ticketWriter.writeString(ticket.cookiePath);
        // footer
        ticketWriter.writeByte(0xff);
        var payload = ticketWriter.buffer;
        // creating hash only for payload
        var ticketHash = crypto.createHmac("sha1", validationKey)
        ticketHash.update(payload);
        var firstSign = ticketHash.digest();
        var prefinal = Buffer.concat([headerBuffer, payload, firstSign]);

        const encryptor = createCypher();
        const encryptedBytes = Buffer.concat([encryptor.update(prefinal), encryptor.final()]);

        var encryptedHash = crypto.createHmac("sha1", validationKey);
        encryptedHash.update(encryptedBytes);
        var secondSign = encryptedHash.digest();

        var final = Buffer.concat([encryptedBytes, secondSign]);

        return final;
    }
    return { encrypt };
}


