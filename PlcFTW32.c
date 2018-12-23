#include "wifi_rfid_reader_sam.h"
#include "wifi_rfid_reader_init.h"
#include "wifi_rfid_reader_uart.h"
#include "wifi_rfid_reader_readcard.h"
#include "Sha256Calc.h"



int sendSAMcount = 0;
volatile char SAM_Exist_Flag = 0;


extern uint64_t Uart1_TimeCnt;
extern volatile uint32_t Uart1_RxIdx;
extern uint8_t  Uart1_RxBuf[];
extern volatile uint8_t UartStatus;


/********************************************************/
//#define PTHREAD_CALC_DGHASH
#define SAM_ECC 1
#define SAM_AES 1

char sem_hash_get = 0;
char sem_hash_compare = 0;

int  dg_len = 0;
char dg_num = 0;
char ret_sam = 0;

uint8_t* dg_src = NULL;
uint8_t  dg1_hash_pth[32],dg11_hash_pth[32],dg15_hash_pth[32];



/******************************SAM - AES********************************/
#if 1
int DGHASH_CPM_ECC1(uint8_t *dg1,uint8_t *dg2,uint8_t *dg3,uint8_t *hash)
{
	if(0 != memcmp(dg1,&hash[18],32))
	{
		Uart3_Printf("memcmp dg1\n");
		return -1;
	}
	if(0 != memcmp(dg2,&hash[57],32))
	{
		Uart3_Printf("memcmp dg2\n");
		return -1;
	}
#if 1
	if(0 != memcmp(dg3,&hash[96],32))
	{
		Uart3_Printf("memcmp dg3\n");
		return -1;
	}
#endif
	return 0;
}

int DGHASH_CPM_ECC2(uint8_t *dg1,uint8_t *dg2,uint8_t *dg3,uint8_t *hash)
{
	if(0 != memcmp(dg1,&hash[21],32))
	{
		Uart3_Printf("memcmp dg1\n");
		return -1;
	}
	if(0 != memcmp(dg2,&hash[138],32))
	{
		Uart3_Printf("memcmp dg2\n");
		return -1;
	}
#if 1
	if(0 != memcmp(dg3,&hash[177],32))
	{
		Uart3_Printf("memcmp dg3\n");
		return -1;
	}
#endif
	return 0;
}

int DG_HASH(uint8_t *buffer,uint8_t *dg,uint8_t *dg_hash,int len)
{
    Sha256Calc s1;
    Sha256Calc_reset(&s1);
    Sha256Calc_calculate(&s1,dg,len);
    memcpy(dg_hash,s1.Value,32);
    return 0;
}

int DG_HASH_to_pthread_cacl(uint8_t *dg,int len,char dg_num_locat)
{
    dg_src = dg;
    dg_len = len;
    dg_num = dg_num_locat;
	//sem_post(&sem_hash_get);
    sem_hash_get = 0x01;
    return 0;
}

int DGHASH_CPM_AES1(uint8_t *dg1,uint8_t *dg2,uint8_t *hash)
{
	uint8_t i;
	
	if(0 != memcmp(dg1,&hash[20],32))
	{
		Uart3_Printf("DGHASH_CPM_AES1 memcmp hash1:\n");
		for(i=20;i <= 20+32;i++)
			Uart3_Printf("%02X ",hash[i]);
		Uart3_Printf("\n");
		return -1;
	}
	if(0 != memcmp(dg2,&hash[20+32+7],32))
	{
		Uart3_Printf("DGHASH_CPM_AES1 memcmp has2:\n");
		for(i=20+32+7;i <= 20+32+32+7;i++)
			Uart3_Printf("%02X ",hash[i]);
		Uart3_Printf("\n");
		return -1;
	}
	return 0;
}

int DGHASH_CPM_AES2(uint8_t *dg1,uint8_t *dg2,uint8_t *hash)
{
	uint8_t i;

	if(0 != memcmp(dg1,&hash[22],32))
	{
		Uart3_Printf("DGHASH_CPM_AES2 memcmp hash1:\n");
		for(i=22;i < 22+32;i++)
			Uart3_Printf("%02X ",hash[i]);
		Uart3_Printf("\n");
		return -1;
	}
	if(0 != memcmp(dg2,&hash[139],32))
	{
		Uart3_Printf("DGHASH_CPM_AES2 memcmp has2:\n");
		for(i=139;i < 139+32;i++)
			Uart3_Printf("%02X ",hash[i]);
		Uart3_Printf("\n");
		return -1;
	}
	return 0;
}

int Apdu12_TimerFun(void)
{
	int len;
	int retval;
	uint8_t i;
	uint8_t buffer[256];
    uint8_t apdu1[] = {0x00,0xA4,0x04,0x00,0x10,0xA0,0x00,0x00,0x00,\
                       0x88,0x53,0x54,0x45,0x4D,0x49,0x4E,0x44,0x45,0x46,0x90,0x01};
    uint8_t apdu2[] = {0x80,0xE3,0x80,0x00,0x14,0x00,0x01,0x02,0x03,0x04,0x05,0x06,\
                       0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13};
    
	if(sem_hash_get == 0x01)//这里要注意，可能不需要进行判断
	{
		sem_hash_get = 0x00;//多出来的

		Uart3_Printf("Apdu12_TimerFun Start... ...\n");
		
		if(dg_num == 1)
		{
			DG_HASH(NULL,dg_src,dg1_hash_pth,dg_len);
			Uart3_Printf("Apdu12_TimerFun -- DG1\n");
		}
		else if(dg_num == 11)
		{
			DG_HASH(NULL,dg_src,dg11_hash_pth,dg_len);
			Uart3_Printf("Apdu12_TimerFun -- DG11\n");
			//sem_post(&sem_hash_compare);
			sem_hash_compare = 0x01;
		}
		else if(dg_num == 12)
		{
			retval = optSAM(apdu1, sizeof(apdu1), buffer, &len);//SAM power on
			if(retval < 0) 
			{
				Uart3_Printf("Apdu12_TimerFun - apdu1 error\n");
				ret_sam = -1;
				return 1;
			}
		#if SAM_AES
			Uart3_Printf("Apdu12_TimerFun - apdu1 recv: ");
			for(i=0;i<len;i++)
				Uart3_Printf("%02X ",buffer[i]);
			Uart3_Printf("\n");
		#endif

			retval = optSAM(apdu2, sizeof(apdu2), buffer, &len);// input SAM PIN
			if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
			{
				Uart3_Printf("Apdu12_TimerFun - apud2 error\n");
				ret_sam = -1;
				return 2;
			}
		#if SAM_AES
			Uart3_Printf("Apdu12_TimerFun - apdu2 recv:\n");
			for(i=0;i<len;i++)
				Uart3_Printf("%02X ",buffer[i]);
			Uart3_Printf("\n");
		#endif
		
			//sem_post(&sem_hash_compare);
			sem_hash_compare = 0x01;
		}
	}
	
	return 0;
}

int optSAM(uint8_t *in, int inlen, uint8_t *out, int *outlen)
{
	int i;
	uint8_t temp;
    uint8_t data[256];
    uint8_t crc = 0x00;
	uint32_t timer_out = 0,delay_i = 0;
	
    memset(data,0,sizeof(data));
    data[0] = 0x6F;
    data[1] = inlen;
    data[6] = sendSAMcount;
    if(sendSAMcount == 0xff){
        sendSAMcount = 0x00;
    }
    sendSAMcount++;
    memcpy(&data[10], in, inlen);
    crc = data[inlen+9];
    for (i = 0; i < inlen + 9; i++)
		crc ^= data[i];
    data[inlen + 10] = crc;

    Uart3_Printf("optSAM-send: ");
    for(i = 0;i < inlen+11;i++){
        Uart3_Printf("%02X ",data[i]);
    }
    Uart3_Printf("\n");

	SAM_SendBytes(data,inlen+11);
	while(1)
	{
		if(UartStatus&0x02) // UART1:SAM数据 接收完成
		{
			USART_ITConfig(USART1, USART_IT_RXNE, DISABLE);
			UartStatus &= 0xFC;
			/*********SAM解析接收到的数据*********/
			
		    Uart3_Printf("optSAM-recv-%d=[1:%d]+9+2: ",Uart1_RxIdx,Uart1_RxBuf[1]);
		    for(i=0;i<Uart1_RxIdx;i++){
		        Uart3_Printf("%02X ",Uart1_RxBuf[i]);
		    }
		    Uart3_Printf("\n");

			temp = Uart1_RxBuf[1];
			if(temp == 0x00)
			{
				Uart3_Printf("------- Waring: optSAM temp copy ---------\n");
				
			}
			
            crc = Uart1_RxBuf[Uart1_RxBuf[1]+7+2];
            for(i = 0;i < Uart1_RxBuf[1]+7+2;i++)
			{
                crc ^= Uart1_RxBuf[i];
            }

            if (Uart1_RxBuf[0] == 0x80 && crc == Uart1_RxBuf[Uart1_RxBuf[1]+8+2]) 
			{
                *outlen = Uart1_RxBuf[1] + 1;
                memcpy(out, &Uart1_RxBuf[9], *outlen);
				
				memset(Uart1_RxBuf, 0, UART1_RX_BUFFLEN);	 
				Uart1_RxIdx = 0;
				USART_ITConfig(USART1, USART_IT_RXNE, ENABLE);	
                return 0;
            }
		
			/************************************************/
			memset(Uart1_RxBuf, 0, UART1_RX_BUFFLEN);	 
			Uart1_RxIdx = 0;
			USART_ITConfig(USART1, USART_IT_RXNE, ENABLE);	
			return -1;
		}
		
		for(delay_i=0;delay_i<10;delay_i++);
		timer_out++;
		if(timer_out > 65500)
		{
			timer_out=0;
			break;
		}
	}

    Uart3_Printf("opt sam timeout\n");
	
    return -1;
}

#ifdef USE_SAM_AES
int getCardInfo_AES(char *uid)
{    
	int i;
	int retval, len;

	Sha256Calc s1;

	uint8_t buff[4];
	uint8_t data_t[256];
	uint8_t buffer[256],Hash_Data[256],dg1[256],dg11[256];//dg15[256],data[256];
	uint8_t dg1_hash[32],dg11_hash[32];//dg15_hash[32];

	uint8_t data1[] = {0x01,0x00,0xA4,0x04,0x0C,0x08,0xA0,0x00,0x00,0x03,0x41,0x00,0x00,0x01};
	uint8_t data2[] = {0x01,0x00,0xC0,0x02,0xA1,0x08};
	uint8_t data3[] = {0x01,0x80,0xF2,0x00,0x00,0x00};
	//uint8_t data4[] = {0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x0F};
	uint8_t data5[] = {0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x1E};
	uint8_t data6[] = {0x01,0x00,0xB0,0x00,0x00,0x03};
	uint8_t data7[] = {0x01,0x00,0xb0,0x00,0x02,0x15};

	uint8_t DG1_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x01};
	uint8_t DG1_data2[]={0x01,0x00,0xB0,0x00,0x00,0x03};
	uint8_t DG1_data3[6]={0x01,0x00,0xB0,0x00,0x02,0x5b};

	#ifdef EF_DG2
	uint8_t DG2_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x02};
	uint8_t DG2_data2[]={0x01,0x00,0xB0,0x00,0x00,0x04};
	uint8_t DG2_data3[7]={0x01,0x00,0xB0,0x00,0x03,0x0D,0x64};
	#endif

	#ifdef EF_DG3
	uint8_t DG3_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x03};
	uint8_t DG3_data2[]={0x01,0x00,0xB0,0x00,0x00,0x04};
	uint8_t DG3_data3[7]={0x01,0x00,0xB0,0x00,0x03,0x04,0x44};
	#endif
	
	uint8_t DG11_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x0B};
	uint8_t DG11_data2[]={0x01,0x00,0xB0,0x00,0x00,0x03};
	uint8_t DG11_data3[6]={0x01,0x00,0xB0,0x00,0x03,0xFF};

	//uint8_t DG15_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x0F};
	//uint8_t DG15_data2[]={0x01,0x00,0xB0,0x00,0x00,0x04};
	//uint8_t DG15_data3[6]={0x01,0x00,0xB0,0x00,0x02,0xFF};

	uint8_t HASH_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x1D};
	uint8_t HASH_data2[]={0x01,0x00,0xB0,0x00,0x00,0x04};
	uint8_t HASH_data3[6]={0x01,0x00,0xB0,0x00,0x03,0xFF};

	//uint8_t sam_poweron[] = {0xB2,0x00,0x01,0x03};
	//uint8_t sam_bute[]    = {0xB1,0x00,0x00,0x18};
	uint8_t apdu1[] = {0x00,0xA4,0x04,0x00,0x10,0xA0,0x00,0x00,0x00,\
	                0x88,0x53,0x54,0x45,0x4D,0x49,0x4E,0x44,0x45,0x46,0x90,0x01};
	uint8_t apdu2[] = {0x80,0xE3,0x80,0x00,0x14,0x00,0x01,0x02,0x03,0x04,0x05,0x06,\
	                0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13};
	uint8_t apdu3[21] = {0x80,0x5a,0x00,0x01,0x10,0x00,0x00,0x00,0x00,0x00,0x00,\
	                  0xf0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x0f,0x01};
	uint8_t apdu4[] = {0x80,0x55,0x0c,0x00,0x0D};//另一个项目要把这个x00 变成0x01
	uint8_t apdu5[77] = {0x84,0x82,0x00,0x00,0x48};
	uint8_t apdu6[256] = {0x80,0x7A,0x9A,0x00,0x6B,0x80,0x20};

	Uart3_Printf("\n\n----- AES SSID START TIMES -----\n");

#ifdef PTHREAD_CALC_DGHASH
	DG_HASH_to_pthread_cacl(NULL,0,12);
#endif
	
	retval = RDM_Channels_Data_Time(data1, sizeof(data1), buffer, &len);//150000-->120000->80000 SSID power on
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00)
	{
		Uart3_Printf("2500000---------------------\n");
		//PN532_RfOff(fd);
		InListPassivTargets_A(buffer, &len);
		retval = RDM_Channels_Data_Time(data1, sizeof(data1), buffer, &len);
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("RDM_Channels_Data 1 error\n");
			return -1;
		}
	}
	 
#if SAM_AES
	Uart3_Printf("buffer of data1:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif

	retval = RDM_Channels_Data_Time(data2, sizeof(data2), buffer, &len);//20000//35000// read ssID csN
#if SAM_AES
	Uart3_Printf("buffer of data2:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	memcpy(buff,&buffer[3],4);//拷贝4个字节卡号放到buff上，后面用到
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 2 error\n");
		return -1;
	}
	sprintf(uid,"%02X%02X%02X%02X%02X%02X%02X%02X",buffer[1],buffer[2],buffer[3],buffer[4],buffer[5],buffer[6],buffer[7],buffer[8]);
	Uart3_Printf("SSIDCardNum:%02X%02X%02X%02X%02X%02X%02X%02X\n",buffer[1],buffer[2],buffer[3],buffer[4],buffer[5],buffer[6],buffer[7],buffer[8]);

	retval = RDM_Channels_Data_Time(data3, sizeof(data3), buffer, &len);// get status SSID
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00)
	{
		Uart3_Printf("RDM_Channels_Data 3 error\n");
		return -1;
	}
	else
	{
	#if SAM_AES
		Uart3_Printf("buffer of data3:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif

		memcpy(&apdu3[7],buff,4); //把卡号(data2处)拷贝到指令里面去
		memcpy(&apdu3[15],buff,4);

	#ifdef PTHREAD_CALC_DGHASH
		Uart3_Printf("power on SAM in the pthread------\n");
		if(ret_sam)
		{
			Uart3_Printf("---- ret_sam != 0 ----\n");
			return -1;
		}
		//sem_wait(&sem_hash_compare);
		while(sem_hash_compare != 0x01)
		{
			//要有超时退出功能
			Uart3_Printf("1-Wait For sem_hash_compare = 0x01\n");
		}
	#else
		retval = optSAM(apdu1, sizeof(apdu1), buffer, &len);//SAM power on
		#if SAM_AES
			Uart3_Printf("buffer of apdu1:\n");
			for(i=0;i<len;i++)
				Uart3_Printf("%02X ",buffer[i]);
			Uart3_Printf("\n");
		#endif
		if (retval < 0) 
		{
		 	Uart3_Printf("apdu1 error\n");
		 	return -1;
		}

		retval = optSAM(apdu2, sizeof(apdu2), buffer, &len);// input SAM PIN
		#if SAM_AES
			Uart3_Printf("buffer of apdu2:\n");
			for(i=0;i<len;i++)
				Uart3_Printf("%02X ",buffer[i]);
			Uart3_Printf("\n");
		#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
	 		Uart3_Printf("apud2 error\n");
	 		return -1;
		}
	#endif

		retval = optSAM(apdu3, sizeof(apdu3), buffer, &len);// Input SSID CSN to SAM
	#if SAM_AES
		Uart3_Printf("buffer of apdu3:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if(retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00 )
		{
			Uart3_Printf("apdu3 error\n");
			return -1;
		}

		retval = optSAM(apdu4, sizeof(apdu4), buffer, &len);// SAM get init data to SSID
		if(retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00 )
		{
			Uart3_Printf("apdu4 error\n");
			return -1;
		}
	#if SAM_AES
		Uart3_Printf("buffer of apdu4:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif

		data_t[0] = 0x01;
		memcpy(&data_t[1],&buffer[1],len-3);

	#if SAM_AES
		Uart3_Printf("data_t: ");
		for(i=0;i<len-2;i++)
			Uart3_Printf("%02X ",data_t[i]);
		Uart3_Printf("\n");
	#endif
	}

	//retval = RDM_Channels_Data_Time(data_t, len-2, buffer, &len);//80000//100000 // Pervious data to SSID
	retval = RDMaaa(data_t, len-2, buffer, &len);//80000//100000 // Pervious data to SSID
#if SAM_AES
	Uart3_Printf("buffer of data_t:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 4 error\n");
		return -1;
	}

	apdu5[4] = len-3;
	memcpy(&apdu5[5],&buffer[1],apdu5[4]);
	retval = optSAM(apdu5, apdu5[4]+5, buffer, &len);// pervious data to SAM  init SSID and SAM finished
#if SAM_AES
	Uart3_Printf("buffer of apdu5:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data apdu5 error\n");
		return -1;
	}

	/* ----------------------- Reading of data group ----------------------- */

	retval = RDM_Channels_Data_Time(data5, sizeof(data5), buffer, &len);//100000  read EF_COM 1
#if SAM_AES
	Uart3_Printf("buffer of data5:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[1] != 0x90 || buffer[2] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 5 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(data6, sizeof(data6), buffer, &len);//60000  read EF_COM 2
#if SAM_AES
	Uart3_Printf("buffer of data6:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 6 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(data7, sizeof(data7), buffer, &len);//100000 read EF_COM 3
#if SAM_AES
	Uart3_Printf("buffer of data7:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 7 error\n");
		return -1;
	}

	/* ----------------------- Reading of EF_DG1 ----------------------- */
	retval = RDM_Channels_Data_Time(DG1_data1, sizeof(DG1_data1), buffer, &len);//20000
#if SAM_AES
	Uart3_Printf("buffer of DG1_data1:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG1_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(DG1_data2, sizeof(DG1_data2), buffer, &len);//30000
#if SAM_AES
	Uart3_Printf("buffer of DG1_data2:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[4]!=0x90||buffer[5]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG1_data2 error\n");
		return -1;
	}
	memcpy(dg1,&buffer[1],3);
	DG1_data3[5]=buffer[2];

	retval = RDM_Channels_Data_Time(DG1_data3, sizeof(DG1_data3), buffer, &len);//70000
#if SAM_AES
	Uart3_Printf("buffer of DG1_data3:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[(len-1)]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG1_data3 error\n");
		return -1;
	}
	memcpy(&dg1[3],&buffer[2],DG1_data3[5]-1);
	
#if SAM_AES
	Uart3_Printf("dg1 src:\n");
	for(i=0;i<DG1_data3[5]+2;i++)
		Uart3_Printf("%02X ",dg1[i]);
	Uart3_Printf("\n");
#endif

#ifdef PTHREAD_CALC_DGHASH
	DG_HASH_to_pthread_cacl(dg1,DG1_data3[5]+2,1);//算dg1的HASH
#else
	//4-----------------
	DG_HASH(buffer,dg1,dg1_hash,DG1_data3[5]+2);//算dg1的HASH
#endif

#if SAM_AES
	Uart3_Printf("dg1_hash:\n");
	for(i = 0;i < 32;i++)
	{
		Uart3_Printf("%02X ",dg1_hash[i]);
	}
	Uart3_Printf("\n");
#endif

	#ifdef EF_DG2
	/* ----------------------- Reading of EF_DG2 ----------------------- */
	Uart3_Printf("------------- EF_DG2 -------------\n");
	retval = RDM_Channels_Data_Time(DG2_data1, sizeof(DG2_data1), buffer, &len);//20000
#if SAM_AES
	Uart3_Printf("buffer of DG2_data1:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG2_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(DG2_data2, sizeof(DG2_data2), buffer, &len);//30000
#if SAM_AES
	Uart3_Printf("buffer of DG2_data2:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[5]!=0x90||buffer[6]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG2_data2 error\n");
		return -1;
	}
	//memcpy(dg1,&buffer[1],3);//pin bi
	DG2_data3[5]=buffer[3];
	DG2_data3[6]=buffer[4];

	retval = RDM_Channels_Data_Time(DG2_data3, sizeof(DG2_data3), buffer, &len);//70000
#if SAM_AES
	Uart3_Printf("buffer of DG2_data3:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[(len-1)]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG2_data3 error\n");
		return -1;
	}
/*	
	memcpy(&dg1[3],&buffer[2],DG1_data3[5]-1);
	
#if SAM_AES
	Uart3_Printf("dg1 src:\n");
	for(i=0;i<DG1_data3[5]+2;i++)
		Uart3_Printf("%02X ",dg1[i]);
	Uart3_Printf("\n");
#endif

#ifdef PTHREAD_CALC_DGHASH
	DG_HASH_to_pthread_cacl(dg1,DG1_data3[5]+2,1);//算dg1的HASH
#else
	//4-----------------
	DG_HASH(buffer,dg1,dg1_hash,DG1_data3[5]+2);//算dg1的HASH
#endif

#if SAM_AES
	Uart3_Printf("dg1_hash:\n");
	for(i = 0;i < 32;i++)
	{
		Uart3_Printf("%02X ",dg1_hash[i]);
	}
	Uart3_Printf("\n");
#endif
*/
	Uart3_Printf("----------------------------------\n");
	#endif

	#ifdef EF_DG3
	/* ----------------------- Reading of EF_DG1 ----------------------- */
	Uart3_Printf("------------- EF_DG3 -------------\n");
	retval = RDM_Channels_Data_Time(DG3_data1, sizeof(DG3_data1), buffer, &len);//20000
#if SAM_AES
	Uart3_Printf("buffer of DG3_data1:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG3_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(DG3_data2, sizeof(DG3_data2), buffer, &len);//30000
#if SAM_AES
	Uart3_Printf("buffer of DG3_data2:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[5]!=0x90||buffer[6]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG3_data2 error\n");
		return -1;
	}
	//memcpy(dg1,&buffer[1],3);//pin bi
	//DG3_data3[5]=buffer[3];
	//DG3_data3[6]=buffer[4];

	retval = RDM_Channels_Data_Time(DG3_data3, sizeof(DG3_data3), buffer, &len);//70000
#if SAM_AES
	Uart3_Printf("buffer of DG3_data3:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[(len-1)]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG3_data3 error\n");
		return -1;
	}
/*
	memcpy(&dg1[3],&buffer[2],DG1_data3[5]-1);
	
#if SAM_AES
	Uart3_Printf("dg1 src:\n");
	for(i=0;i<DG1_data3[5]+2;i++)
		Uart3_Printf("%02X ",dg1[i]);
	Uart3_Printf("\n");
#endif

#ifdef PTHREAD_CALC_DGHASH
	DG_HASH_to_pthread_cacl(dg1,DG1_data3[5]+2,1);//算dg1的HASH
#else
	//4-----------------
	DG_HASH(buffer,dg1,dg1_hash,DG1_data3[5]+2);//算dg1的HASH
#endif

#if SAM_AES
	Uart3_Printf("dg1_hash:\n");
	for(i = 0;i < 32;i++)
	{
		Uart3_Printf("%02X ",dg1_hash[i]);
	}
	Uart3_Printf("\n");
#endif
*/
	Uart3_Printf("----------------------------------\n");
	#endif


	/* ----------------------- Reading of EF_DG11 ----------------------- */
	retval = RDM_Channels_Data_Time(DG11_data1, sizeof(DG11_data1), buffer, &len);//30000
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG11_data1 error\n");
		return -1;
	}
#if SAM_AES
	Uart3_Printf("buffer of DG11_data1:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif

	retval = RDM_Channels_Data_Time(DG11_data2, sizeof(DG11_data2), buffer, &len);//30000
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG11_data2 error\n");
		return -1;
	}
#if SAM_AES
	Uart3_Printf("buffer of DG11_data2:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	memcpy(dg11,&buffer[1],3);
	DG11_data3[5]=buffer[3];

	//retval = RDM_Channels_Data_Time(DG11_data3, sizeof(DG11_data3), buffer, &len);//120000
	retval = RDMaaa(DG11_data3, sizeof(DG11_data3), buffer, &len);//120000
#if SAM_AES
	Uart3_Printf("buffer of DG11_data3:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG11_data3 error\n");
		return -1;
	}
	memcpy(&dg11[3],&buffer[1],DG11_data3[5]);
	
#if SAM_AES
	Uart3_Printf("dg11 src:\n");
	for(i=0;i<DG11_data3[5]+3;i++)
		Uart3_Printf("%02X ",dg11[i]);
	Uart3_Printf("\n");
#endif

#ifdef PTHREAD_CALC_DGHASH
	DG_HASH_to_pthread_cacl(dg11,DG11_data3[5]+3,11);//算dg11的HASH
#else
	//2--------------------
	DG_HASH(buffer,dg11,dg11_hash,DG11_data3[5]+3);//算dg11的HASH
#endif

#if SAM_AES
	Uart3_Printf("dg11_hash:\n");
	for(i = 0;i < 32;i++)
	{
		Uart3_Printf("%02X ",dg11_hash[i]);
	}
	Uart3_Printf("\n");
#endif

	/* ----------------------- Reading of EF_SOD ----------------------- */
	retval = RDM_Channels_Data_Time(HASH_data1, sizeof(HASH_data1), buffer, &len);//30000
#if SAM_AES
	Uart3_Printf("buffer of HASH_data1:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data HASH_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(HASH_data2, sizeof(HASH_data2), buffer, &len);//30000
#if SAM_AES
	Uart3_Printf("buffer of HASH_data2:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data HASH_data2 error\n");
		return -1;
	}

	if(buffer[3] < 0xf0)//根据后面要接收数据的长度判断是不是有图片指纹的HASH，这里没有
	{
		HASH_data3[5]=buffer[3];
		//retval = RDM_Channels_Data_Time(HASH_data3, sizeof(HASH_data3), buffer, &len);//110000
		retval = RDMaaa(HASH_data3, sizeof(HASH_data3), buffer, &len);//110000
	#if SAM_AES
		Uart3_Printf("buffer of HASH_data3 not picture and fingerprint:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
		{
			Uart3_Printf("RDM_Channels_Data HASH_data3 error\n");
			return -1;
		}

	#ifdef  PTHREAD_CALC_DGHASH
		//sem_wait(&sem_hash_compare);
		while(sem_hash_compare != 0x01)
		{
			Uart3_Printf("Wait for sem_hash_compare = 0x01\n");
		}

		Uart3_Printf("dg1_hash---pthread:\n");
		for(i = 0;i < 32;i++){
			Uart3_Printf("%02X ",dg1_hash_pth[i]);
		}
		Uart3_Printf("\n");

		Uart3_Printf("dg11_hash------pthread:\n");
		for(i = 0;i < 32;i++){
			Uart3_Printf("%02X ",dg11_hash_pth[i]);
		}
		Uart3_Printf("\n");

		retval = DGHASH_CPM_AES1(dg1_hash_pth,dg11_hash_pth,buffer);  //没有图片指纹的 HASH比较
	#else
		//memcpy(dg1_hash,dg1_hash_pth,32);
		//memcpy(dg11_hash,dg11_hash_pth,32);
		retval = DGHASH_CPM_AES1(dg1_hash,dg11_hash,buffer);  //没有图片指纹的 HASH比较
	#endif

		if(retval < 0)
		{
			Uart3_Printf("DGHASH FAILDE   AES-------------card22222-------------\n");
			return -1;
		}

		memcpy(&Hash_Data[0],&buffer[9],82);
		Sha256Calc_reset(&s1);
		Sha256Calc_calculate(&s1, Hash_Data, 82);
		memcpy(&apdu6[7],&(s1.Value),32);
		apdu6[39]=0x9E;
		memcpy(&apdu6[40],&buffer[92],buffer[92]+1);
		apdu6[4] = 32+apdu6[40]+2+1+1;

	#if SAM_AES
		Uart3_Printf("apdu6:\n");
		for(i=0;i<255;i++)
			Uart3_Printf("%02X ",apdu6[i]);
		Uart3_Printf("\n");
	#endif

		retval = optSAM(apdu6, apdu6[4]+5, buffer, &len);
	#if SAM_AES
		Uart3_Printf("buffer of apdu6:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("opt SAM error \n");
			return -2;
		}
	}
	else   //根据后面要接收数据的长度判断是不是有图片指纹的HASH，这里有
	{
		HASH_data3[5]=buffer[3];

		// 8--------------
		retval = RDM_Channels_Data_Time(HASH_data3, sizeof(HASH_data3), buffer, &len);//110000
	#if SAM_AES
		Uart3_Printf("buffer of HASH_data3 have picture and fingerprint:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
		{
			Uart3_Printf("RDM_Channels_Data HASH_data3\n");
			return -1;
		}

	#ifdef  PTHREAD_CALC_DGHASH
		//sem_wait(&sem_hash_compare);
		while(sem_hash_compare != 0x01)
		{
			Uart3_Printf("Wait for sem_hash_compare = 0x01\n");
		}
		Uart3_Printf("dg1_hash---pthread:\n");
		for(i = 0;i < 32;i++){
			Uart3_Printf("%02X ",dg1_hash_pth[i]);
		}
		Uart3_Printf("\n");

		Uart3_Printf("dg11_hash------pthread:\n");
		for(i = 0;i < 32;i++){
			Uart3_Printf("%02X ",dg11_hash_pth[i]);
		}
		Uart3_Printf("\n");

		retval = DGHASH_CPM_AES2(dg1_hash_pth,dg11_hash_pth,buffer);  //没有图片指纹的HASH比较
	#else
		//9 --------------------------
		retval = DGHASH_CPM_AES2(dg1_hash,dg11_hash,buffer); //没有图片指纹的HASH比较
	#endif
		if(retval < 0)
		{
			Uart3_Printf("DGHASH FAILDE   AES -----------------picture--------------\n");
			return -1;
		}
	
		memcpy(&Hash_Data[0],&buffer[9],162);
	#if SAM_AES
		Uart3_Printf("Hash_Data:\n");
		for(i=0;i<162;i++)
			Uart3_Printf("%02X ",Hash_Data[i]);
		Uart3_Printf("\n");
	#endif
		Sha256Calc_reset(&s1);
		Sha256Calc_calculate(&s1, Hash_Data, 162);
		memcpy(&apdu6[7],&(s1.Value),32);
		apdu6[39]=0x9E;
		memcpy(&apdu6[40],&buffer[172],buffer[172]+1);
		apdu6[4] = 32+apdu6[40]+2+1+1;

		//10--------------------
		retval = optSAM(apdu6, apdu6[4]+5, buffer, &len);
	#if SAM_AES
		Uart3_Printf("buffer of apdu6:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("opt SAM error \n");
			return -2;
		}
	}

	Uart3_Printf("==== ---- SAM OK ---- ====\n");

    return 0;
}
#endif //#ifdef USE_SAM_AES

#endif

#ifdef USE_SAM_ECC
int getCardInfo_ECC(char *uid)
{
	int i;
	int retval, len = 0;
	int index = 0;
	int temp = 0;
	
	Sha256Calc s1;
	
	uint8_t bigbuffer[512];
	uint8_t buffer[256], data[256],Hash_Data[256],dg1[256],dg11[256],dg15[256];
	uint8_t dg1_hash[32],dg11_hash[32],dg15_hash[32];
	uint8_t data1[] = {0x01,0x00,0xA4,0x04,0x0C,0x08,0xA0,0x00,0x00,0x03,0x41,0x00,0x00,0x01};
	uint8_t data2[] = {0x01,0x00,0xC0,0x02,0xA1,0x08};
	uint8_t data3[] = {0x01,0x80,0xF2,0x00,0x00,0x00};
	uint8_t data4[] = {0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x0F};
	uint8_t data5[] = {0x01,0x00,0xB0,0x00,0x1F,0x01,0x41};
	uint8_t data6[] = {0x01,0x00,0xB0,0x00,0x20,0x41};
	uint8_t data7[14] = {0x01,0x00};

	uint8_t data8[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x1E};
	uint8_t data9[]={0x01,0x00,0xB0,0x00,0x00,0x03};
	uint8_t data10[6]={0x01,0x00,0xB0,0x00,0x02,0xFF};

	uint8_t DG1_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x01};
	uint8_t DG1_data2[]={0x01,0x00,0xB0,0x00,0x00,0x03};
	uint8_t DG1_data3[6]={0x01,0x00,0xB0,0x00,0x02,0xFF};

	uint8_t DG11_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x0B};
	uint8_t DG11_data2[]={0x01,0x00,0xB0,0x00,0x00,0x03};
	uint8_t DG11_data3[6]={0x01,0x00,0xB0,0x00,0x03,0xFF};

	uint8_t DG15_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x0F};
	uint8_t DG15_data2[]={0x01,0x00,0xB0,0x00,0x00,0x04};
	uint8_t DG15_data3[6]={0x01,0x00,0xB0,0x00,0x02,0xFF};

	uint8_t HASH_data1[]={0x01,0x00,0xA4,0x00,0x0C,0x02,0x01,0x1D};
	uint8_t HASH_data2[]={0x01,0x00,0xB0,0x00,0x00,0x04};
	uint8_t HASH_data3[6]={0x01,0x00,0xB0,0x00,0x04,0xFF};

	//uint8_t sam_poweron[] = {0xB2,0x00,0x01,0x03};
	//uint8_t sam_bute[]    = {0xB1,0x00,0x00,0x18};
	uint8_t apdu1[] = {0x00,0xA4,0x04,0x00,0x10,0xA0,0x00,0x00,0x00,\
	                0x88,0x53,0x54,0x45,0x4D,0x49,0x4E,0x44,0x45,0x46,0x90,0x01};
	uint8_t apdu2[] = {0x80,0xE3,0x80,0x00,0x14,0x00,0x01,0x02,0x03,0x04,0x05,0x06,\
	                0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13};

	uint8_t apdu3[70] = {0x80,0x40,0x00,0x00,0x41};
	uint8_t apdu4[] = {0x80,0x55,0x30,0x00,0x0D};
	uint8_t apdu5[77] = {0x84,0x82,0x00,0x00,0x48};

	uint8_t apdu6[256] = {0x80,0x7A,0x9A,0x00,0x6B,0x80,0x20};

	retval = RDM_Channels_Data_Time(data1, sizeof(data1), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data1\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[1] != 0x90 || buffer[2] != 0x00) 
	{
		Uart3_Printf("---- 1 err ----\n");
		//PN532_RfOff(fd);
		InListPassivTargets_A(buffer, &len);
		retval = RDM_Channels_Data_Time(data1, sizeof(data1), buffer, &len);
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("RDM_Channels_Data 1 error\n");
			return -1;
		}
	}

	retval = RDM_Channels_Data_Time(data2, sizeof(data2), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data2\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 2 error\n");
		return -1;
	}
	memcpy(data, &buffer[1], 8);
	sprintf(uid,"%02X%02X%02X",buffer[4],buffer[5],buffer[6]);

	retval = RDM_Channels_Data_Time(data3, sizeof(data3), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data3\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 3 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(data4, sizeof(data4), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data4\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 4 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(data5, sizeof(data5), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data5\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 5 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(data6, sizeof(data6), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data6\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 6 error\n");
		return -1;
	}
	else
	{
		memcpy(&apdu3[5], &buffer[1], 65);
		
		retval = optSAM(apdu1, sizeof(apdu1), buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of apdu1\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 ) 
		{
			Uart3_Printf("optSAM apdu1 error\n");
			return -2;
		}

		retval = optSAM(apdu2, sizeof(apdu2), buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of apdu2\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00)
		{
			Uart3_Printf("optSAM apdu2 error\n");
			return -2;
		}

		retval = optSAM(apdu3, sizeof(apdu3), buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of apdu3\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("optSAM apdu3 error\n");
			return -2;
		}

		retval = optSAM(apdu4, sizeof(apdu4), buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of apdu4\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("optSAM apdu4 error\n");
			return -2;
		}
		memcpy(&data7[1], &buffer[1], 13);
		Uart3_Printf("data7: ");
		for(i = 0;i < 14;i++)
			Uart3_Printf(" %02X ",data7[i]);
		Uart3_Printf("\n");
	}

	//retval = RDM_Channels_Data_Time(data7, sizeof(data7), buffer, &len);
	retval = RDMaaa(data7, sizeof(data7), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data7\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
	{
		Uart3_Printf("RDM_Channels_Data 7 error\n");
		return -1;
	}
	else
	{
		memcpy(&apdu5[5], &buffer[1], buffer[2] + 4);
		apdu5[4] = buffer[2] + 2;
		retval = optSAM(apdu5, apdu5[6] + 5+2, buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of apdu5\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 ) 
		{
			Uart3_Printf("optSAM apdu5 error\n");
			return -2;
		}

		if (0x90 == buffer[len-2] && 0x00 == buffer[len-1]) 
		{
			Uart3_Printf("SSID:%s\n", uid);
		} 
		else 
		{
			Uart3_Printf("------------\n");
			return -3;
		}
	}

	//add by hwz 20150619
	retval = RDM_Channels_Data_Time(data8, sizeof(data8), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data8\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data 8 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(data9, sizeof(data9), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data9\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data 9 error\n");
		return -1;
	}
	data10[5]=buffer[2];

	retval = RDM_Channels_Data_Time(data10, sizeof(data10), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of data10\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data 10 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(DG1_data1, sizeof(DG1_data1), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG1_data1\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG1_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(DG1_data2, sizeof(DG1_data2), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG1_data2\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG1_data2 error\n");
		return -1;
	}
	memcpy(dg1,&buffer[1],3);
	DG1_data3[5]=buffer[2];

	retval = RDM_Channels_Data_Time(DG1_data3, sizeof(DG1_data3), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG1_data3\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[(len-1)]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG1_data3 error\n");
		return -1;
	}
	memcpy(&dg1[3],&buffer[2],DG1_data3[5]-1);

#if SAM_ECC
	Uart3_Printf("dg1:\n");
	for(i = 0;i < DG1_data3[5]+2;i++)
	{
		Uart3_Printf("%02X ",dg1[i]);
	}
	Uart3_Printf("\n");
#endif
	DG_HASH(buffer,dg1,dg1_hash,DG1_data3[5]+2); //算dg1的HASH
#if SAM_ECC
	Uart3_Printf("dg1_hash:\n");
	for(i = 0;i < 32;i++)
	{
		Uart3_Printf("%02X ",dg1_hash[i]);
	}
	Uart3_Printf("\n");
#endif

	retval = RDM_Channels_Data_Time(DG11_data1, sizeof(DG11_data1), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG11_data1\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG11_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(DG11_data2, sizeof(DG11_data2), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG11_data2\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG11_data2 error\n");
		return -1;
	}
	memcpy(dg11,&buffer[1],3);
	DG11_data3[5]=buffer[3];

	//retval = RDM_Channels_Data_Time(DG11_data3, sizeof(DG11_data3), buffer, &len);
	retval = RDMaaa(DG11_data3, sizeof(DG11_data3), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG11_data3\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG11_data3 error\n");
		return -1;
	}
	memcpy(&dg11[3],&buffer[1],DG11_data3[5]);

#if SAM_ECC
	Uart3_Printf("dg11:\n");
	for(i = 0;i < DG11_data3[5]+3;i++)
		Uart3_Printf("%02X ",dg11[i]);
	Uart3_Printf("\n");
#endif
	DG_HASH(buffer,dg11,dg11_hash,DG11_data3[5]+3);//算dg11的HASH
#if SAM_ECC
	Uart3_Printf("dg11_hash:\n");
	for(i = 0;i < 32;i++)
		Uart3_Printf("%02X ",dg11_hash[i]);
	Uart3_Printf("\n");
#endif

	retval = RDM_Channels_Data_Time(DG15_data1, sizeof(DG15_data1), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG15_data1\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG15_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(DG15_data2, sizeof(DG15_data2), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG15_data2\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG15_data2 error\n");
		return -1;
	}
	memcpy(dg15,&buffer[1],4);
	DG15_data3[5]=buffer[2];

	retval = RDM_Channels_Data_Time(DG15_data3, sizeof(DG15_data3), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of DG15_data3\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[(len-2)]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data DG15_data3 error\n");
		return -1;
	}
	memcpy(&dg15[4],&buffer[3],DG15_data3[5]+4);

#if SAM_ECC
	Uart3_Printf("dg15:\n");
	for(i = 0;i < DG15_data3[5]+2;i++)
		Uart3_Printf("%02X ",dg15[i]);
	Uart3_Printf("\n");
#endif
	DG_HASH(buffer,dg15,dg15_hash,DG15_data3[5]+2);//算dg15的HASH
#if SAM_ECC
	Uart3_Printf("dg15_hash:\n");
	for(i = 0;i < 32;i++)
		Uart3_Printf("%02X ",dg15_hash[i]);
	Uart3_Printf("\n");
#endif

	retval = RDM_Channels_Data_Time(HASH_data1, sizeof(HASH_data1), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of HASH_data1:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data HASH_data1 error\n");
		return -1;
	}

	retval = RDM_Channels_Data_Time(HASH_data2, sizeof(HASH_data2), buffer, &len);
#if SAM_ECC
	Uart3_Printf("buffer of HASH_data2:\n");
	for(i=0;i<len;i++)
		Uart3_Printf("%02X ",buffer[i]);
	Uart3_Printf("\n");
#endif
	if(retval<0||buffer[len-2]!=0x90||buffer[len-1]!=0x00)
	{
		Uart3_Printf("RDM_Channels_Data HASH_data2 error\n");
		return -1;
	}

	if(buffer[2] == 0x81)//根据后面要接收数据的长度判断是不是有图片指纹的HASH,这里没有
	{
		HASH_data3[5]=buffer[3];
		//retval = RDM_Channels_Data_Time(HASH_data3, sizeof(HASH_data3), buffer, &len);
		retval = RDMaaa(HASH_data3, sizeof(HASH_data3), buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of HASH_data3:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if(retval<0||buffer[len-2]!=0x90||buffer[(len-1)]!=0x00)
		{
			Uart3_Printf("RDM_Channels_Data HASH_data3 error\n");
			return -1;
		}
		memcpy(bigbuffer,&buffer[1],len-1);
		
	#if SAM_ECC
		Uart3_Printf("bigbuffer:\n");
		for(i=0;i<len-1;i++)
			Uart3_Printf("%02X ",bigbuffer[i]);
		Uart3_Printf("\n");
	#endif

		retval = DGHASH_CPM_ECC1(dg1_hash,dg11_hash,dg15_hash,bigbuffer); //没有图片指纹的HASH比较
		if(retval < 0)
		{
			Uart3_Printf("DGHASH FAILDE error\n");
			return -1;
		}
		memcpy(&Hash_Data[0],&bigbuffer[7],121);

		Sha256Calc_reset(&s1);
		Sha256Calc_calculate(&s1, Hash_Data, 121);

		memcpy(&apdu6[7],&(s1.Value),32);
		apdu6[39]=0x9E;
		memcpy(&apdu6[40],&bigbuffer[129],bigbuffer[129]+1);
		Uart3_Printf("bigbuffer[129]=%02X\n",bigbuffer[129]);

		apdu6[4] = 32+apdu6[40]+2+1+1;
	#if SAM_ECC
		Uart3_Printf("apdu6:\n");
		for(i=0;i<apdu6[4]+5;i++)
			Uart3_Printf("%02X ",apdu6[i]);
		Uart3_Printf("\n");
	#endif

		retval = optSAM(apdu6, apdu6[4]+5, buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of apdu6\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("optSAM apdu6 - error\n");
			return -2;
		}
	}
	else if(buffer[2] == 0x82) //根据后面要接收数据的长度判断是不是有图片指纹的HASH，这里有
	{
		HASH_data3[5] =0xff-15;
		index = 0;
		temp = ((buffer[3] << 8)|buffer[4])-0xff+15;
		//长度太长，分两次读，这里是第一次
		retval = RDM_Channels_Data_Time(HASH_data3, sizeof(HASH_data3), buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of HASH_data3:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if(retval<0||buffer[len-2]!=0x90||buffer[(len-1)]!=0x00)
		{
			Uart3_Printf("RDM_Channels_Data HASH_data3 error\n");
			return -1;
		}
		HASH_data3[4] = 0xff-15+4;
		HASH_data3[5] = temp;
		memcpy(bigbuffer,&buffer[1],len);
		index = len;

		//第二次读
		retval = RDM_Channels_Data_Time(HASH_data3, sizeof(HASH_data3), buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of HASH_data3_1:\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if(retval<0||buffer[len-2]!=0x90||buffer[(len-1)]!=0x00)
		{
			Uart3_Printf("RDM_Channels_Data HASH_data3_1 error\n");
			return -1;
		}

		memcpy(&bigbuffer[index-3],&buffer[1],len-1);
	#if SAM_ECC
		Uart3_Printf("bigbuffer:\n");
		for(i=0;i<len+index-4;i++)
			Uart3_Printf("%02X ",bigbuffer[i]);
		Uart3_Printf("\n");
	#endif

		retval = DGHASH_CPM_ECC2(dg1_hash,dg11_hash,dg15_hash,bigbuffer);//有图片指纹的HASH比较
		if(retval < 0)
		{
			Uart3_Printf("DGHASH FAILDE error\n");
			return -1;
		}
		memcpy(&Hash_Data[0],&bigbuffer[8],201);
	#if SAM_ECC
		Uart3_Printf("Hash_Data:\n");
		for(i=0;i<201;i++)
			Uart3_Printf("%02X ",Hash_Data[i]);
		Uart3_Printf("\n");
	#endif
		Sha256Calc_reset(&s1);
		Sha256Calc_calculate(&s1, Hash_Data, 201);

		memcpy(&apdu6[7],&(s1.Value),32);
		apdu6[39]=0x9E;
		memcpy(&apdu6[40],&bigbuffer[210],bigbuffer[210]+1);
		Uart3_Printf("bigbuffer[210]=%02X\n",bigbuffer[210]);

		apdu6[4] = 32+apdu6[40]+2+1+1;
	#if SAM_ECC
		Uart3_Printf("apdu6:\n");
		for(i=0;i<apdu6[4]+5;i++)
			Uart3_Printf("%02X ",apdu6[i]);
		Uart3_Printf("\n");
	#endif

		retval = optSAM(apdu6, apdu6[4]+5, buffer, &len);
	#if SAM_ECC
		Uart3_Printf("buffer of apdu6\n");
		for(i=0;i<len;i++)
			Uart3_Printf("%02X ",buffer[i]);
		Uart3_Printf("\n");
	#endif
		if (retval < 0 || buffer[len-2] != 0x90 || buffer[len-1] != 0x00) 
		{
			Uart3_Printf("optSAM apdu6 - error\n");
			return -2;
		}
	}
	else
	{
		Uart3_Printf("buffer of Hash_data2 error");
		return -1;
	}

	Uart3_Printf("CHECK SSID SUCCESS!!!\n");

	return 0;
}
#endif //#ifdef USE_SAM_ECC


/***********************************************************************/

int sendSAMpowerData(uint8_t *in, int inlen)
{
	int i;
	int ret = -1;
	uint32_t timer_out = 0,delay_i = 0;

    in[6] = sendSAMcount;
    if(sendSAMcount == 0xff){
        sendSAMcount = 0x00;
    }
    sendSAMcount++;

    in[inlen-1] = in[inlen-2];
    for(i=inlen-2;i>0;i--){
        in[inlen - 1] ^= in[i - 1];
    }

    Uart3_Printf("SAMPowerUpData_S: ");
    for(i=0;i<inlen;i++){
        Uart3_Printf("%02X ",in[i]);
    }
    Uart3_Printf("\n");

	SAM_SendBytes(in,inlen);
	while(1)
	{
		if(UartStatus&0x02) // UART1:SAM数据 接收完成
		{
			USART_ITConfig(USART1, USART_IT_RXNE, DISABLE);
			UartStatus &= 0xFC;
			/*********SAM解析接收到的数据*********/
			
		    Uart3_Printf("SAMPowerUpData_R: ");
		    for(i=0;i<Uart1_RxIdx;i++){
		        Uart3_Printf("%02X ",Uart1_RxBuf[i]);
		    }
		    Uart3_Printf("\n");
			
			switch(in[0])
			{
                case 0x66:
                    if(Uart1_RxBuf[0] == 0x86)
                        ret = 0;
                    else
                        ret = -1;
					break;
					
                case 0x6B:
                    if(Uart1_RxBuf[0] == 0x83)
						ret = 0;
                    else
                        ret = -1;
					break;
					
                case 0x62:
                    if(Uart1_RxBuf[0] == 0x80)
						ret = 0;
                    else
                        ret = -1;
					break;
					
                case 0x63:
                    if(Uart1_RxBuf[0] == 0x81)
						ret = 0;
                    else
                        ret = -1;
					break;
					
                case 0x6C:
                    if(Uart1_RxBuf[0] == 0x82)
						ret = 0;
                    else
                        ret = -1;
					break;
					
				default:ret = -1;
					break;
             }
			/************************************************/
			memset(Uart1_RxBuf, 0, UART1_RX_BUFFLEN);	 
			Uart1_RxIdx = 0;
			USART_ITConfig(USART1, USART_IT_RXNE, ENABLE);	
			return ret;
		}
		
		for(delay_i=0;delay_i<10;delay_i++);
		timer_out++;
		if(timer_out > 65500)
		{
			timer_out=0;
			break;
		}
	}
	
	Uart3_Printf("Read SAM PowerOn Data Timeout\n");
	
	return -1;
}

int optSAMpowerOn(void)
{
    uint8_t power1[] = {0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x65};
    uint8_t power2[] = {0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x64};
    uint8_t power3[] = {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40,\
                        0x54, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74};
    uint8_t power4[] = {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40,\
                        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE7};
    uint8_t power5[] = {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40,\
                        0xC3, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, 0xC1};
    uint8_t power6[] = {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x40,\
                        0xC3, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, 0xC0};
    uint8_t power7[] = {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x40,\
                        0xC3, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, 0xC3};
    uint8_t power8[] = {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x40,\
                        0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70};
    uint8_t power9[] = {0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x6D};
    uint8_t power10[]= {0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x6C};
    uint8_t power11[]= {0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x03, 0x00, 0x00, 0x6F};
    uint8_t power12[]= {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x40,\
                        0x54, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7D};
    uint8_t power13[]= {0x6B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x40,\
                        0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E};
    uint8_t power14[]= {0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x6E};
    uint8_t power15[]= {0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x00, 0x00, 0x6D};
    uint8_t power16[]= {0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x63};

    if(0 > sendSAMpowerData(power1,sizeof(power1))){
        Uart3_Printf("powerSAM fail step1\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power2,sizeof(power2))){
        Uart3_Printf("powerSAM fail step2\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power3,sizeof(power3))){
        Uart3_Printf("powerSAM fail step3\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power4,sizeof(power4))){
        Uart3_Printf("powerSAM fail step4\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power5,sizeof(power5))){
        Uart3_Printf("powerSAM fail step5\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power6,sizeof(power6))){
        Uart3_Printf("powerSAM fail step6\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power7,sizeof(power7))){
        Uart3_Printf("powerSAM fail step7\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power8,sizeof(power8))){
        Uart3_Printf("powerSAM fail step8\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power9,sizeof(power9))){
        Uart3_Printf("powerSAM fail step9\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power10,sizeof(power10))){
        Uart3_Printf("powerSAM fail step10\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power11,sizeof(power11))){
        Uart3_Printf("powerSAM fail step11\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power12,sizeof(power12))){
        Uart3_Printf("powerSAM fail step12\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power13,sizeof(power13))){
        Uart3_Printf("powerSAM fail step13\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power14,sizeof(power14))){
        Uart3_Printf("powerSAM fail step14\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power15,sizeof(power15))){
        Uart3_Printf("powerSAM fail step15\n");
        return -1;
    }
    if(0 > sendSAMpowerData(power16,sizeof(power16))){
        Uart3_Printf("powerSAM fail step16\n");
        return -1;
    }
	
    return 1;
}

void SAM_Power_On_Driver(void)
{
	int i=0;

	while(i<5)
	{
		i++;
		if(optSAMpowerOn() > 0)
		{
			SAM_Exist_Flag = 0x01;
			Uart3_Printf("powerSAM Success\n");
			Delay_Ms(300);
			BELL_ON();
			Delay_Ms(300);
			BELL_OFF();
			break;
		}
	}
}



