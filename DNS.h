//
// Created by jialun zhang on 19/5/2023.
//

#ifndef DNS_SYSTEM_DNS_H
#define DNS_SYSTEM_DNS_H

struct DNS_Header{
    unsigned short id; //2字节（16位）
    unsigned short flags;

    unsigned short questionsNum; //问题数
    unsigned short answerNum; //回答数
    unsigned short authorityNum;
    unsigned short additionalNum;
};

struct DNS_Query{
    unsigned char *name;        //要查询的主机名（长度不确定）
    unsigned short qtype;
    unsigned short qclass;
    int length;     //主机名的长度
};

struct DNS_RR{
    unsigned char *SearchName;
    int SearchNameLen;
    unsigned short type;
    unsigned int ttl;
    unsigned short data_len;
    unsigned char *ip;
    unsigned char *CName;
    unsigned char *MXName;
    unsigned char *PTRName;
    unsigned short class;
};


int is_pointer(int in) {
    return ((in & 0xC0) == 0xC0);
}

void dns_parse_QueryName(unsigned char* chunk, unsigned char* ptr, char* out, int* len) {
    int flag = 0, n = 0;
    char* string = out + (*len);
    while (1) {
        flag = (int)ptr[0];
        if (flag == 0) break;
        if (is_pointer(flag)) {
            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_QueryName(chunk, ptr, out, len);
            break;
        }
        else {
            ptr++;
            memcpy(string, ptr, flag);
            ptr += flag;
            string += flag;
            *len += flag;
            if ((int)ptr[0] != 0) {
                memcpy(string, ".", 1);
                string ++;
                (*len) ++;
            }
        }

    }

}


#endif //DNS_SYSTEM_DNS_H
