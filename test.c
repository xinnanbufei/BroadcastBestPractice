#include <string.h>
#include "wifi_rfid_reader_def.h"
#include "wifi_rfid_reader_init.h"
#include "wifi_rfid_reader_led.h"
#include "wifi_rfid_reader_uart.h"
#include "wifi_rfid_reader_timer.h"
#include "wifi_rfid_reader_pn532.h"
#include "wifi_rfid_reader_flash.h"
#include "wifi_rfid_reader_user.h"
#include "wifi_rfid_reader_sam.h"



volatile uint32_t gTimeCnt = 0;

#if 0
static void RCC_Config(void);
static void RCC_Printf(void);
#endif

void Wifi_Reader_Init(void)
{
	SystemClock_Init();
	RCC_Configuration();
	GPIO_Configuration();
	UART_Configuration();
	Timer2_Configuration();
	Flash_W25QXX_Configuration();
	WiFi_Reader_Parameter();
	PN532_Configuration();
	SAM_Power_On_Driver();
	
	//IWDG_Configuration();
}
#if 0
static void RCC_Config(void)
{
#if 0	
	ErrorStatus HSEStartUpStatus;

	/*将外设RCC寄存器重设为缺省值*/
	RCC_DeInit();

	/*设置外部高速晶振（HSE）*/
	RCC_HSEConfig(RCC_HSE_ON);

	/*等待HSE起振*/
	HSEStartUpStatus = RCC_WaitForHSEStartUp();

	/*SUCCESS：HSE晶振稳定且就绪*/
	if(HSEStartUpStatus == SUCCESS)
	{
		/*设置AHB时钟（HCLK）*/ 
		RCC_HCLKConfig(RCC_SYSCLK_Div1);  //RCC_SYSCLK_Div1——AHB时钟= 系统时钟

		/* 设置高速AHB时钟（PCLK2）*/ 
		RCC_PCLK2Config(RCC_HCLK_Div1);   //RCC_HCLK_Div1——APB2时钟= HCLK

		/*设置低速AHB时钟（PCLK1）*/    
		RCC_PCLK1Config(RCC_HCLK_Div1);   //RCC_HCLK_Div2——APB1时钟= HCLK / 2

		/*设置FLASH存储器延时时钟周期数*/
		FLASH_SetLatency(FLASH_Latency_2);    //FLASH_Latency_2  2延时周期

		/*选择FLASH预取指缓存的模式*/  
		FLASH_PrefetchBufferCmd(FLASH_PrefetchBuffer_Enable);       // 预取指缓存使能

		/*设置PLL时钟源及倍频系数*/ 
		RCC_PLLConfig(RCC_PLLSource_HSE_Div3, RCC_PLLMul_3);     
		// PLL的输入时钟= HSE时钟频率；RCC_PLLMul_9——PLL输入时钟x 9

		/*使能PLL */
		RCC_PLLCmd(ENABLE); 

		/*检查指定的RCC标志位(PLL准备好标志)设置与否*/   
		while(RCC_GetFlagStatus(RCC_FLAG_PLLRDY) == RESET)      
		{
		}

		/*设置系统时钟（SYSCLK）*/ 
		RCC_SYSCLKConfig(RCC_SYSCLKSource_PLLCLK); 
		//RCC_SYSCLKSource_PLLCLK——选择PLL作为系统时钟

		/* PLL返回用作系统时钟的时钟源*/
		while(RCC_GetSYSCLKSource() != 0x08)        //0x08：PLL作为系统时钟
		{ 
		}
	}
#endif
}

static void RCC_Printf(void)
{
	RCC_ClocksTypeDef ClockInfo;
		
	Uart3_Printf("RCC->CR: %08X\n",RCC->CR);
	Uart3_Printf("RCC->ICSCR: %08X\n",RCC->ICSCR);
	Uart3_Printf("RCC->CFGR: %08X\n",RCC->CFGR);
	Uart3_Printf("RCC->CIR: %08X\n",RCC->CIR);
	Uart3_Printf("RCC->AHBRSTR: %08X\n",RCC->AHBRSTR);
	Uart3_Printf("RCC->APB2RSTR: %08X\n",RCC->APB2RSTR);
	Uart3_Printf("RCC->APB1RSTR: %08X\n",RCC->APB1RSTR);
	Uart3_Printf("RCC->AHBENR: %08X\n",RCC->AHBENR);
	Uart3_Printf("RCC->APB2ENR: %08X\n",RCC->APB2ENR);
	Uart3_Printf("RCC->APB1ENR: %08X\n",RCC->APB1ENR);
	Uart3_Printf("RCC->AHBLPENR: %08X\n",RCC->AHBLPENR);
	Uart3_Printf("RCC->APB2LPENR: %08X\n",RCC->APB2LPENR);
	Uart3_Printf("RCC->APB1LPENR: %08X\n",RCC->APB1LPENR);
	Uart3_Printf("RCC->CSR: %08X\n",RCC->CSR);

	RCC_GetClocksFreq(&ClockInfo);
	Uart3_Printf("SYSCLK: %08X\n",ClockInfo.SYSCLK_Frequency);
	Uart3_Printf("HCLK: %08X\n",ClockInfo.HCLK_Frequency);
	Uart3_Printf("PCLK1: %08X\n",ClockInfo.PCLK1_Frequency);
	Uart3_Printf("PCLK2: %08X\n",ClockInfo.PCLK2_Frequency);
}
#endif
void SystemClock_Init(void)
{
    /* Setup SysTick Timer for 1ms interrupts 
        *
        * x/2.097MHz = 1ms,so x = 2097
        * x/32MHz = 1ms,so x = 32000
        *
	*/
	
	if (SysTick_Config(2097))
	{
		/* Capture error */
		while (1);
	}
	
	/* Configure the SysTick handler priority */
	NVIC_SetPriority(SysTick_IRQn, 0x0);
}

void RCC_Configuration(void)
{
	RCC_AHBPeriphClockCmd(RCC_AHBPeriph_GPIOA | RCC_AHBPeriph_GPIOB | RCC_AHBPeriph_GPIOC, ENABLE);
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_USART1, ENABLE);
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART2 | RCC_APB1Periph_USART3, ENABLE);
}

void GPIO_Configuration(void)
{
	Led_Init();
	Bell_Init();
}

void UART_Configuration(void)
{
	Uart1_Configuration();//USART1 ----- SAM
	Uart2_Configuration();//USART2 ----- WIFI
	Uart3_Configuration();//USART3 ----- Debug	
}

void IWDG_Configuration(void)
{
	/* IWDG timeout equal to 250 ms (the timeout may varies due to LSI frequency dispersion) */
	
	/* Enable write access to IWDG_PR and IWDG_RLR registers */
	IWDG_WriteAccessCmd(IWDG_WriteAccess_Enable);
	
	/* IWDG counter clock: LSI/16 = 37KHz/16 =  2.3125KHz */
  	IWDG_SetPrescaler(IWDG_Prescaler_16);

	/* Set counter reload value to obtain 1S IWDG TimeOut */
	IWDG_SetReload(2312);

	/* Reload IWDG counter */
	IWDG_ReloadCounter();

	/* Enable IWDG (the LSI oscillator will be enabled by hardware) */
	IWDG_Enable();
}

void Delay_Ms(uint32_t ms)
{
	gTimeCnt = 0;
	while(gTimeCnt < ms) ;
}

void Delay_Us(uint16_t us)
{
	uint8_t j;
	uint16_t i = 0;

	while(i++ < us)
	{
		for(j=0;j<10;j++);
	}
}

void Delay_100Us(uint16_t delayTime)
{
	volatile unsigned short int i,j;

	for(i=0;i<delayTime;i++)
		for(j=0;j<500;j++) {;}
}







