#define MQTTCLIENT_QOS2 1
#include <memory.h>
#include <string>
#include "MQTTClient.h"
#define DEFAULT_STACK_SIZE -1
#include "linux.cpp"

#define MQTT_VERSION 3
const char* clientId = "mbed-icraggs";
const char* topic = "test/user1";
const char* hostname = "localhost";
const int port = 1883;
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
    rc = connect2Server(hostname, port, clientId, topic, ipstack, client);
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

