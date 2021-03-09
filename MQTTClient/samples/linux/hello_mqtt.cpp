#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define MQTTCLIENT_QOS2 1
#include <memory.h>
#include <string>
#include "MQTTClient.h"
#define DEFAULT_STACK_SIZE -1
//#include "linux.cpp"

#ifdef __cplusplus
extern "C" {
#endif
    #include "mbedtls/net_sockets.h"
    #include "mbedtls/debug.h"
    #include "mbedtls/ssl.h"
    #include "mbedtls/entropy.h"
    #include "mbedtls/ctr_drbg.h"
    #include "mbedtls/error.h"
    #include "mbedtls/certs.h"
    #include "mbedtls/sha256.h"
#ifdef __cplusplus
}
#endif

#define LOG_WRITE printf
#define mbedtls_fprintf    fprintf

#define FLAG_UNSET -1

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
mbedtls_x509_crt clicert;
mbedtls_pk_context pkey;

char server_name[256] = "localhost";  //"10.10.37.100"
#define SERVER_PORT "8883" //"9883"
#define CERT_FILE "/home/j/dreame/tls/ca.crt"

#define MQTT_VERSION 3
const char* clientId = "mbed-icraggs";
const char* topic = "test/user1";
const char* hostname = "localhost";
// const int port = 1883;
const char* user = "user1";
const char* passwd = "user1";
int arrivedcount = 0;

typedef struct _CONNECTION_INFO{
    int port;
    std::string hostname;
    std::string username;
    std::string passwd;
    std::string topic;
} CONNECTION_INFO;


class IPStack{
public:
    static void my_debug(void *ctx, int level, const char *file, int line, const char *str){
        ((void) level);

        mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
        fflush((FILE *) ctx);
    }

    IPStack(){}
    int verify_cacert(){
        int ret;  uint32_t flags;
        const char *pers = "ssl_client1";

        // 0. Initialize the RNG and the session data
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_x509_crt_init(&clicert);
        mbedtls_pk_init(&pkey);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        LOG_WRITE("\n  . Seeding the random number generator...\n"); fflush(stdout);
        mbedtls_entropy_init(&entropy);
        if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
            LOG_WRITE( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
            return -1;
        }
        // 1. Initialize certificates
        LOG_WRITE("  . Loading the CA root certificate ...\n"); fflush(stdout);
        //~/dreame/tls
        ret = mbedtls_x509_crt_parse_file( &cacert, CERT_FILE);
        if(ret < 0) { 
            LOG_WRITE(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret ); 
            return -1;
        }
        // 2. Start the connection
        LOG_WRITE("  . Connecting to tcp/%s/%s...\n", server_name, SERVER_PORT); fflush(stdout);
        if((ret = mbedtls_net_connect(&server_fd, server_name, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
            LOG_WRITE(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
            return -1;
        }
        // 3. Setup stuff
        LOG_WRITE("  . Setting up the SSL/TLS structure...\n"); fflush(stdout);
        if((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            LOG_WRITE(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);  
            return -1;
        }
        //MBEDTLS_SSL_VERIFY_NONE, MBEDTLS_SSL_VERIFY_REQUIRED
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED); 
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
        if((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
            LOG_WRITE(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);  
            return -1;
        }
        if((ret = mbedtls_ssl_set_hostname(&ssl, server_name)) != 0) {
            LOG_WRITE(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
            return -1;
        }
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
        
        // 4. Handshake
        LOG_WRITE("  . Performing the SSL/TLS handshake...\n");  fflush(stdout);
        while((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                LOG_WRITE(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
                return -1;
            }
        }
        // 5. Verify the server certificate
        LOG_WRITE("  . Verifying peer X.509 certificate...");
        if((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
            char vrfy_buf[512];
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags);
            LOG_WRITE("failed, %s\n", vrfy_buf);
            return -1;
        }
        else {
            LOG_WRITE(" OK!\n");
            LOG_WRITE("______________________________________________________________\n");
        }

        return 0;
    }

    int connect(const char* hostname, int port){
        int rc = 0;
        //**********************************************************************************************************
        // verify the server certificate and login if verify successfully
        //**********************************************************************************************************
        if(-1 == verify_cacert()) {
            LOG_WRITE("verify cacert failed!\n");
            return -1;
        }else{
            printf("verify cacert OK\n");
        }
        mysock = server_fd.fd;
        return rc;
    }

    // return -1 on error, or the number of bytes read
    // which could be 0 on a read timeout
    int read(unsigned char* buffer, int len, int timeout_ms){
		// struct timeval interval = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
		// if (interval.tv_sec < 0 || (interval.tv_sec == 0 && interval.tv_usec <= 0)){
		// 	interval.tv_sec = 0;
		// 	interval.tv_usec = 100;
		// }

		// setsockopt(mysock, SOL_SOCKET, SO_RCVTIMEO, (char *)&interval, sizeof(struct timeval));

		int bytes = 0;
        int i = 0; const int max_tries = 10;
		while (bytes < len){
            int rc = mbedtls_ssl_read( &ssl, &buffer[bytes], (size_t)(len - bytes) );
			// int rc = ::recv(mysock, &buffer[bytes], (size_t)(len - bytes), 0);
			if (rc <= 0){
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                bytes = -1;
                break;
			} else bytes += rc;
            if (++i >= max_tries) break;
            if (rc == 0) break;
		}
		return bytes;
    }

    int write(unsigned char* buffer, int len, int timeout){
        struct timeval tv;

        tv.tv_sec = 0;  /* 30 Secs Timeout */
        tv.tv_usec = timeout * 1000;  // Not init'ing this can cause strange errors

        setsockopt(mysock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(struct timeval));
        int rc = mbedtls_ssl_write(&ssl, buffer, len);
        //int	rc = ::write(mysock, buffer, len);
        printf("write rc %d\n", rc);
        return rc;
    }

	int disconnect(){
        mbedtls_ssl_close_notify(&ssl);

        mbedtls_net_free(&server_fd);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return 0;
		//return ::close(mysock);
	}

private:
    int mysock;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
};


class Countdown{
public:
    Countdown(){}
    Countdown(int ms){
        countdown_ms(ms);
    }

    bool expired(){
        struct timeval now, res;
        gettimeofday(&now, NULL);
        timersub(&end_time, &now, &res);
        //printf("left %d ms\n", (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000);
        //if (res.tv_sec > 0 || res.tv_usec > 0)
        //	printf("expired %d %d\n", res.tv_sec, res.tv_usec);
        return res.tv_sec < 0 || (res.tv_sec == 0 && res.tv_usec <= 0);
    }

    void countdown_ms(int ms){
        struct timeval now;
        gettimeofday(&now, NULL);
        struct timeval interval = {ms / 1000, (ms % 1000) * 1000};
        //printf("interval %d %d\n", interval.tv_sec, interval.tv_usec);
        timeradd(&now, &interval, &end_time);
    }


    void countdown(int seconds){
        struct timeval now;
        gettimeofday(&now, NULL);
        struct timeval interval = {seconds, 0};
        timeradd(&now, &interval, &end_time);
    }


    int left_ms(){
        struct timeval now, res;
        gettimeofday(&now, NULL);
        timersub(&end_time, &now, &res);
        //printf("left %d ms\n", (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000);
        return (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000;
    }

private:
	struct timeval end_time;
};


void messageArrived(MQTT::MessageData& md){
    MQTT::Message &message = md.message;

    printf("Message %d arrived: qos %d, retained %d, dup %d, packetid %d\n", 
		++arrivedcount, message.qos, message.retained, message.dup, message.id);
    printf("Payload %.*s\n", (int)message.payloadlen, (char*)message.payload);
}

int connect2Server(const std::string &hostname, const int port, const std::string &clientId, const std::string &topic, IPStack &ipstack, MQTT::Client<IPStack, Countdown> &client){
    printf("Connecting to %s:%d\n", hostname.c_str(), port);
    int rc = ipstack.connect(hostname.c_str(), port);
	if (rc != 0){
        printf("rc from TCP connect is %d\n", rc);
        return rc;
    }
    printf("MQTT connecting\n");
    std::string username = "user1";
    std::string passwd = "user1";
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;       
    data.MQTTVersion = MQTT_VERSION;
    data.clientID.cstring = (char*)(clientId.c_str());
    data.username.cstring = (char*)(username.c_str());
    data.password.cstring = (char*)(passwd.c_str());
    rc = client.connect(data);
	if (rc != 0){
        printf("rc from MQTT connect is %d\n", rc);
        return rc;
    }

	printf("MQTT connected\n");
    return 0;
}

int sendMsg(MQTT::Client<IPStack, Countdown> & client, const std::string &topic, const std::string &msg, MQTT::QoS qos= MQTT::QOS0);
int sendMsg(MQTT::Client<IPStack, Countdown> & client, const std::string &topic, const std::string &msg, MQTT::QoS qos){
    int rc = 0;
    MQTT::Message message;
    message.qos = qos;
    message.retained = false;
    message.dup = false;
    message.payload = (void*)(msg.c_str());
    message.payloadlen = msg.size() + 1;
    printf("msg:%s, size:%d(strlen:%d)\n", msg.c_str(), msg.size(), strlen(msg.c_str()));
    rc = client.publish(topic.c_str(), message);
	if (rc != 0){
        printf("Error %d from sending QoS 0 message\n", rc);
    }
    // else while (arrivedcount == 0)
    //     client.yield(100);
    return rc;
}

int main(int argc, char* argv[]){
    IPStack ipstack = IPStack();
    MQTT::Client<IPStack, Countdown> client = MQTT::Client<IPStack, Countdown>(ipstack);
    int rc = 0;
    rc = connect2Server(hostname, 1, clientId, topic, ipstack, client);
    if(rc != 0){
        return rc;
    }
    rc = client.subscribe(topic, MQTT::QOS2, messageArrived);
    if (rc != 0){
        printf("rc from MQTT subscribe is %d\n", rc);
    }
    // QoS 0
    char buf[100];
    snprintf(buf, 100, "Hello World!  QoS 0 message from app version %d", MQTT_VERSION);
    sendMsg(client, topic, buf, MQTT::QOS0);
    // QoS 1
    snprintf(buf, 100, "Hello World!  QoS 1 message from app version %d", MQTT_VERSION);
    sendMsg(client, topic, buf, MQTT::QOS1);
    // QoS 2
    snprintf(buf, 100, "Hello World!  QoS 2 message from app version %d", MQTT_VERSION);
    sendMsg(client, topic, buf, MQTT::QOS2);
    
    rc = client.unsubscribe(topic);
    if (rc != 0)
        printf("rc from unsubscribe was %d\n", rc);
    rc = client.disconnect();
    if (rc != 0)
        printf("rc from disconnect was %d\n", rc);
    
    ipstack.disconnect();
    printf("Finishing with %d messages received\n", arrivedcount);

    return 0;
}

