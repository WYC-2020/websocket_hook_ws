/*
* The MIT License (MIT)
* Copyright(c) 2020 BeikeSong

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "pch.h"
#include "ws_endpoint.h"
#include "ws_endpoint.h"

WebSocketEndpoint::WebSocketEndpoint()
{
    //networklayer_ = nt;
    nt_write_cb_ = NULL;
    ws_handshake_completed_ = false;
}

WebSocketEndpoint::WebSocketEndpoint(nt_write_cb write_cb)
{
    //networklayer_ = nt;
    nt_write_cb_ = write_cb;
    ws_handshake_completed_ = false;
}

WebSocketEndpoint::~WebSocketEndpoint() {}

int32_t WebSocketEndpoint::process(const char *readbuf, int32_t size)
{
    return from_wire(readbuf, size);
}

int32_t WebSocketEndpoint::process(const char *readbuf, int32_t size, nt_write_cb write_cb, void *work_data)
{
    if (write_cb == NULL || work_data == NULL)
    {
       // std::cout << "WebSocketEndpoint - Attention: write cb is NULL! It will skip current read buf!" << std::endl;
        return 0;
    }

    nt_write_cb_ = write_cb;
    nt_work_data_ = work_data;

    return from_wire(readbuf, size);
}

#include "openssl/rsa.h"
#include "openssl/pem.h"
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"ssleay32.lib")

// 私钥解密
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey)
{
	std::string strRet;
	RSA *rsa = RSA_new();
	BIO *keybio;
	keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);

	// 此处有三种方法
	// 1, 读取内存里生成的密钥对，再从内存生成rsa
	// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa
	// 3，直接从读取文件指针生成rsa
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	// 解密函数
	int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	// 释放内存
	free(decryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

// 公钥解密
std::string rsa_pub_decrypt(const std::string &cipherText, const std::string &pubKey)
{
	std::string strRet;
	RSA *rsa = RSA_new();
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey.c_str(), -1);
	PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	// 解密函数  
	int ret = RSA_public_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	// 释放内存  
	free(decryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

int32_t WebSocketEndpoint::from_wire(const char *readbuf, int32_t size)
{
    fromwire_buf_.append(readbuf, size);
    while (true)
    {
        int64_t nrcv = parse_packet(fromwire_buf_);
        if (nrcv > 0)
        { // for next one
            // clear used data
            int64_t n_used = fromwire_buf_.getoft();

            fromwire_buf_.erase(nrcv);
            fromwire_buf_.resetoft();
            if (fromwire_buf_.length() == 0)
            {
                return nrcv;
            }
            else
            {
                continue;
            }
        }
        else if (nrcv == 0)
        { // contueue recving
            fromwire_buf_.resetoft();
            break;
        }
        else
        {
            return -1;
        }
    }
	fromwire_buf_.erase(fromwire_buf_.length());
    // make it happy
    return 0;
}

int32_t WebSocketEndpoint::to_wire(const char *writebuf, int64_t size)
{
    //networklayer_->toWire(writebuf,size);
    //if (nt_write_cb_ == NULL || nt_work_data_ == NULL || writebuf == NULL || size <= 0)
    //{
    //    return 0;
    //}

    nt_write_cb_(const_cast<char *>(writebuf), size, nt_work_data_);
    return 0;
}

int64_t WebSocketEndpoint::parse_packet(ByteBuffer &input)
{
    WebSocketPacket wspacket;
    if (!ws_handshake_completed_)
    {
        uint32_t nstatus = 0;
        nstatus = wspacket.recv_handshake(input);
        if (nstatus != 0)
        {
            return -1;
        }

        if (wspacket.get_hs_length() == 0)
        {
            // not enough data for a handshake message
            // continue recving data
            return 0;
        }

        std::string hs_rsp;
        wspacket.pack_handshake_rsp(hs_rsp);
        to_wire(hs_rsp.c_str(), hs_rsp.length());
        ws_handshake_completed_ = true;

        return wspacket.get_hs_length();
    }
    else
    {
        uint64_t ndf = wspacket.recv_dataframe(input);

        // continue recving data until get an entire frame
        if (ndf == 0)
        {
            return 0;
        }

        if (ndf > 0xFFFFFFFF)
        {
			OutputDebugStringFomart("Attention:frame data length exceeds the max value of a uint32_t varable!");
        }

        ByteBuffer &payload = wspacket.get_payload();
        message_data_.append(payload.bytes(), payload.length());

        // now, we have a entire frame
        if (wspacket.get_fin() == 1)
        {
            process_message_data(wspacket, message_data_);
            message_data_.erase(message_data_.length());
            message_data_.resetoft();
            return ndf;
        }

        return ndf;
    }

    return -1;
}

int32_t WebSocketEndpoint::process_message_data(WebSocketPacket &packet, ByteBuffer &frame_payload)
{
    switch (packet.get_opcode())
    {
    case WebSocketPacket::WSOpcode_Continue:
        user_defined_process(packet, frame_payload);
        break;
    case WebSocketPacket::WSOpcode_Text:
        user_defined_process(packet, frame_payload);
        break;
    case WebSocketPacket::WSOpcode_Binary:
        user_defined_process(packet, frame_payload);
        break;
    case WebSocketPacket::WSOpcode_Close:
		ws_handshake_completed_ = false;
        //user_defined_process(packet, frame_payload);
        break;
    case WebSocketPacket::WSOpcode_Ping:
        user_defined_process(packet, frame_payload);
        break;
    case WebSocketPacket::WSOpcode_Pong:
        user_defined_process(packet, frame_payload);
        break;
    default:
        break;
    }
    return 0;
}

// we directly return what we get from client
// user could modify this function
int32_t WebSocketEndpoint::user_defined_process(WebSocketPacket &packet, ByteBuffer &frame_payload)
{
    // print received websocket payload from client
    std::string str_recv(frame_payload.bytes(), frame_payload.length());

	to_wire(str_recv.c_str(), str_recv.length());

    //WebSocketPacket wspacket;
    //// set FIN and opcode
    //wspacket.set_fin(1);
    //wspacket.set_opcode(packet.get_opcode());
    //// set payload data
    //wspacket.set_payload(frame_payload.bytes(), frame_payload.length());
    //ByteBuffer output;
    //// pack a websocket data frame
    //wspacket.pack_dataframe(output);
    //// send to client
    //to_wire(output.bytes(), output.length());

	return 0;
}
