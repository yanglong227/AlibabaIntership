#include <string.h>
#include<bitset>
#include<iostream>
#include <fstream>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include <algorithm>
#include<vector>
#include <time.h>
#include <fcntl.h>

#define MAPUNIT 65537
using namespace std;


vector<vector< unsigned int > *> linkHeadUnit(MAPUNIT,NULL);     //vector的头。
vector<string> splitresult;

void split(string str,string pattern) //字符串分割函数
{
    splitresult.clear();
    string::size_type pos;
    //vector<string> result;
    str+=pattern; //扩展字符串以方便操作
    int size=str.size();

    for(int i=0; i<size; ++i)
    {
        pos=str.find(pattern,i);
        if(pos<size)
        {
            string s=str.substr(i,pos-i);
            splitresult.push_back(s);
            i=pos+pattern.size()-1;
        }
    }
    //return splitresult;
}


int IfValidateIPAddress(const string IP)
{
    int i=0;
    int strLen=IP.size();
    if(strLen<7)  // 合法IP地址最小长度为
        return 0;
    int xiegangindex=-1;
    int dotCount=0;
    while(IP[i]!='\0' )     //保证 IP地址中只有数字、点和斜杠三种字符。
    {
        if(IP[i]>='0' &&IP[i]<='9')
            ++i;
        else if (IP[i]=='.')
        {
            ++dotCount;
            ++i;
        }
        else if (IP[i]=='/')
        {

            xiegangindex=i;
            cout<< "strLen:"<<strLen<<"    xiegangindex:"<<xiegangindex<<endl;
            if((xiegangindex+1)==strLen)    //有斜杠，但是没有掩码号
                return 0;
            ++i;
        }
        else
            return 0;
    }


    char charIP[25];      //字符数组的 IP地址。。
    i=0;
    while(IP[i]!='\0' )
    {
        charIP[i]=IP[i];
        ++i;
    }
    charIP[i]= '\0';

    const char *d=".";
    int intgerResult[4];
    char *p=strtok(charIP,d);
    i=0;
    while(p)
    {
        intgerResult[i++]=atoi(p);
        p=strtok(NULL,d);
    }

    for(i=0;i<4;++i)
        if(intgerResult[i]>255)
        {
            return 0;
        }

    if(dotCount!=3)
        return 0;
    return 1;
}



int hasMask(const string ipaddress)        //判断一个ip 地址是否有掩码，有返回，没有返回
{
    int strlen=ipaddress.size();
    int i=0;
    while(i<strlen&&ipaddress[i]!='/')
        ++i;
    if(i==strlen)
        return 0;
    return 1;
}

string getIp(const char * address)             //求得 IP地址的字符串
{
    string result;
    char *targetPointer=strstr(address,"ip=" );

   
    if(NULL!=targetPointer)
    {
        int targetIndex=targetPointer-address;
        split(address+targetIndex, "&");
        vector<string> iptemp(splitresult);
        int size=iptemp[0].size();
        result=iptemp[0].substr(3,size-3);
    }
    return result;
}


int getMaskBit(const string IP)  //get mask bits from IP address
{
    int i=0;
    int strLen=IP.size();
    while(IP[i]!='/' )
    {
        ++i;
    }
    int index=strLen-i;
    string sub=IP.substr(i+1,index);
    char temp[5];
    i=0;
    while(sub[i]!='\0' )
    {
        temp[i]=sub[i];
        ++i;
    }
    return(atoi(temp));
}

unsigned int IP2unsignedintnew(const string IP)    //IP地址转换为unsigned  int       新版本
{
    int IPlen=IP.size();
    char charIP[50];      //字符数组的 IP地址。。
    int i=0;
    while(IP[i]!='\0' )
    {
        charIP[i]=IP[i];
        ++i;
    }
    charIP[i]= '\0';

    const char *d=".";
    int intgerResult[4];
    char *p=strtok(charIP,d);
    i=0;
    while(p)
    {
        intgerResult[i++]=atoi(p);
        p=strtok(NULL,d);
    }
    unsigned int result=0;   //最后的无符号结果
    unsigned int binaryNumber[32];     //2进制的IP 地址
    unsigned int maskShift=0;   //掩码移位数
    unsigned int mask=1;   //去和 result进行或运算的掩码

    for(int h=0;h<32;++h)
        binaryNumber[h]=0;


    int binarybit=0;
    for(i=3;i>=0;--i)     //构建了 IP地址的二进制表示。
    {    
        int currentNumber=intgerResult[i];
        for(int h=0;h<8;++h)
        {
            binaryNumber[binarybit]=currentNumber%2;
            currentNumber=currentNumber/2;
            ++binarybit;
        }
    }

    if(!hasMask(IP))
    {
        maskShift=0;
        for(int h=0;h<32;++h)
        {
            if(binaryNumber[h]==1)
            {
                result=result|mask;
            }
            ++maskShift;
            mask=1;
            mask=mask<<maskShift;
        }
    }
    else
    {
        int maskBit=getMaskBit(IP);  // 掩码的位数
        maskShift=31;    
        for(int h=31;h>=32-maskBit;--h)
        {
            mask=mask<<maskShift;
            if(binaryNumber[h]==1)
            {
                result=result|mask;
            }
            --maskShift;
            mask=1;
        }
    }
    return result;
}


int IFAccept(const string IP)      //判断本IP 是否给予通过，表示通过，表示拒绝
{
    unsigned int IPSum=IP2unsignedintnew(IP);
    // if(hasMask(IP))
    // {
    //       IPSum+=1;
    // }
    unsigned int headId=IPSum%MAPUNIT;
    if(NULL==linkHeadUnit[headId])
    {
        //            cout<< "IP:"<<IP<<"      Accept"<<endl;
        return 1;
    }
    else
    {
        vector< unsigned int >::iterator it=find((*linkHeadUnit[headId]).begin(),
                (*linkHeadUnit[headId]).end(),IPSum);
        if(it==(*linkHeadUnit[headId]).end())
        {
            //                cout<< "IP:"<<IP<<"     Accept"<<endl;
            return 1;
        }
        //        cout<< "IP:"<<IP<<"       Decilne"<<endl;
        return 0;
    }
}



void ConstructFilterRule(const char *src)
{

    string IP(src);
    //  if(!IfValidateIPAddress(IP))
    //{
    //      cout<< "IP:"<<IP<<" 为非法IP！ "<<endl;
    //           return;
    // }

    unsigned int netSum=IP2unsignedintnew(IP);                   //netSum为子网号的和
    unsigned int IPSum;
    int headId;

    if(!hasMask(IP))                              //没有掩码的情况，直接插入这个 unsinged int值
    {
        IPSum=netSum;                       //如果没子网，子网号的和就为 IP地址的值；
        headId=IPSum%MAPUNIT;
        if(NULL==linkHeadUnit[headId])             //本条链表为空。
        {
            linkHeadUnit[headId]= new vector<unsigned int>();
            (*linkHeadUnit[headId]).push_back(IPSum);
        }
        else                                           //链表不为空，直接插入
        {
        //    vector< unsigned int >::iterator it=find((*linkHeadUnit[headId]).begin(),
        //            (*linkHeadUnit[headId]).end(),IPSum);
        //    if(it==(*linkHeadUnit[headId]).end())  
            {
                (*linkHeadUnit[headId]).push_back(IPSum);
            }
        }
        //  cout<<"IP:"<<IP<<" 已经加入规则库 "<<endl;
    }
    else                                     //有掩码的情况，需要循环插入来实现
    {
        int maskBit=getMaskBit(IP);
        int maxNetNumber=(int )pow(2.0,32-maskBit);
        for(int i=1;i<maxNetNumber-1;++i)
        {
            IPSum=netSum+i;
            headId=IPSum%MAPUNIT;
            if(NULL==linkHeadUnit[headId])             //本条链表为空。
            {
                linkHeadUnit[headId]= new vector<unsigned int>();
                (*linkHeadUnit[headId]).push_back(IPSum);
            }
            else                                           //链表不为空，直接插入
            {
          //      vector< unsigned int >::iterator it=find((*linkHeadUnit[headId]).begin(),
          //              (*linkHeadUnit[headId]).end(),IPSum);
          //      if(it==(*linkHeadUnit[headId]).end())  
                {
                    (*linkHeadUnit[headId]).push_back(IPSum);
                }
            }
        }
        //cout<<"IP:"<<IP<<" 已经加入规则库 "<<endl;
    }
}


int main()
{
    char IPTemp[1600];
    int acceptCount=0;
    int totalquery=0;
    int a=clock();
    FILE * rulefile=fopen( "/home/yanglong/ipfilter/ip_blacklist" ,"r");
    FILE * queryFile=fopen( "/home/yanglong/programming/queryfile" ,"w");
    int queryOutputHandle=fileno(queryFile);
    cout<< "*******construct filter rule...***********" <<endl;
    while(fgets(IPTemp,1600,rulefile))           //循环读取字典，建立过滤规则
    {
        ConstructFilterRule(IPTemp);
    }
    FILE * targetfile=fopen( "/home/yanglong/ipfilter/query" ,"r");
    string targetIP;
    //int strLen=0;
    string IPString;
    cout<< "********IP  Matching.....*************" <<endl;
    while(fgets(IPTemp,1600,targetfile))
    {
        IPString=getIp(IPTemp);
        ++totalquery;
       // strLen=strlen(IPTemp);
        if(IPString.size()==0)
        {
            ++acceptCount;
            fputs(IPTemp,queryFile);
            //write(queryOutputHandle,IPTemp,strLen);
        }
        //cout<<"This line has NO IP"<<endl;
        else  
            if(IFAccept(IPString))
            {
                ++acceptCount;
                fputs(IPTemp,queryFile);
                //write(queryOutputHandle,IPTemp,strLen);
            }
    }
    int b=clock();
    cout<< "AcceptCount:"<<acceptCount<<endl;
    cout<< "TimeCost:"<<(b-a)/1000000<<"s" <<endl;
    cout<< "totalquery"<<totalquery<<endl;
    return 0;
}
  
