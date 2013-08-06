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


vector<vector< unsigned int > *> linkHeadUnit(MAPUNIT,NULL);     //vector��ͷ��
vector<string> splitresult;

void split(string str,string pattern) //�ַ����ָ��
{
    splitresult.clear();
    string::size_type pos;
    //vector<string> result;
    str+=pattern; //��չ�ַ����Է������
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
    if(strLen<7)  // �Ϸ�IP��ַ��С����Ϊ
        return 0;
    int xiegangindex=-1;
    int dotCount=0;
    while(IP[i]!='\0' )     //��֤ IP��ַ��ֻ�����֡����б�������ַ���
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
            if((xiegangindex+1)==strLen)    //��б�ܣ�����û�������
                return 0;
            ++i;
        }
        else
            return 0;
    }


    char charIP[25];      //�ַ������ IP��ַ����
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



int hasMask(const string ipaddress)        //�ж�һ��ip ��ַ�Ƿ������룬�з��أ�û�з���
{
    int strlen=ipaddress.size();
    int i=0;
    while(i<strlen&&ipaddress[i]!='/')
        ++i;
    if(i==strlen)
        return 0;
    return 1;
}

string getIp(const char * address)             //��� IP��ַ���ַ���
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

unsigned int IP2unsignedintnew(const string IP)    //IP��ַת��Ϊunsigned  int       �°汾
{
    int IPlen=IP.size();
    char charIP[50];      //�ַ������ IP��ַ����
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
    unsigned int result=0;   //�����޷��Ž��
    unsigned int binaryNumber[32];     //2���Ƶ�IP ��ַ
    unsigned int maskShift=0;   //������λ��
    unsigned int mask=1;   //ȥ�� result���л����������

    for(int h=0;h<32;++h)
        binaryNumber[h]=0;


    int binarybit=0;
    for(i=3;i>=0;--i)     //������ IP��ַ�Ķ����Ʊ�ʾ��
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
        int maskBit=getMaskBit(IP);  // �����λ��
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


int IFAccept(const string IP)      //�жϱ�IP �Ƿ����ͨ������ʾͨ������ʾ�ܾ�
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
    //      cout<< "IP:"<<IP<<" Ϊ�Ƿ�IP�� "<<endl;
    //           return;
    // }

    unsigned int netSum=IP2unsignedintnew(IP);                   //netSumΪ�����ŵĺ�
    unsigned int IPSum;
    int headId;

    if(!hasMask(IP))                              //û������������ֱ�Ӳ������ unsinged intֵ
    {
        IPSum=netSum;                       //���û�����������ŵĺ;�Ϊ IP��ַ��ֵ��
        headId=IPSum%MAPUNIT;
        if(NULL==linkHeadUnit[headId])             //��������Ϊ�ա�
        {
            linkHeadUnit[headId]= new vector<unsigned int>();
            (*linkHeadUnit[headId]).push_back(IPSum);
        }
        else                                           //����Ϊ�գ�ֱ�Ӳ���
        {
        //    vector< unsigned int >::iterator it=find((*linkHeadUnit[headId]).begin(),
        //            (*linkHeadUnit[headId]).end(),IPSum);
        //    if(it==(*linkHeadUnit[headId]).end())  
            {
                (*linkHeadUnit[headId]).push_back(IPSum);
            }
        }
        //  cout<<"IP:"<<IP<<" �Ѿ��������� "<<endl;
    }
    else                                     //��������������Ҫѭ��������ʵ��
    {
        int maskBit=getMaskBit(IP);
        int maxNetNumber=(int )pow(2.0,32-maskBit);
        for(int i=1;i<maxNetNumber-1;++i)
        {
            IPSum=netSum+i;
            headId=IPSum%MAPUNIT;
            if(NULL==linkHeadUnit[headId])             //��������Ϊ�ա�
            {
                linkHeadUnit[headId]= new vector<unsigned int>();
                (*linkHeadUnit[headId]).push_back(IPSum);
            }
            else                                           //����Ϊ�գ�ֱ�Ӳ���
            {
          //      vector< unsigned int >::iterator it=find((*linkHeadUnit[headId]).begin(),
          //              (*linkHeadUnit[headId]).end(),IPSum);
          //      if(it==(*linkHeadUnit[headId]).end())  
                {
                    (*linkHeadUnit[headId]).push_back(IPSum);
                }
            }
        }
        //cout<<"IP:"<<IP<<" �Ѿ��������� "<<endl;
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
    while(fgets(IPTemp,1600,rulefile))           //ѭ����ȡ�ֵ䣬�������˹���
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
  
