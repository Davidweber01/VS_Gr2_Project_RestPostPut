/*
 * timer.c
 *
 *  Created on: 07.11.2019
 *      Author: bboeck
 */



#include <stdint.h>
#include <stdbool.h>

#include "inc/hw_memmap.h"          // for several predefined macros like "GPIO_PORTN_BASE"
#include "inc/hw_ints.h"            // Macros that define the interrupt assignment on Tiva C Series MCUs (e.g. "INT_TIMER0A")
#include "driverlib/sysctl.h"       // clock
#include "driverlib/interrupt.h"
#include "driverlib/timer.h"

#include "timerIntCtrl.h"


// The system clock speed.
extern uint32_t g_ui32SysClock;



void timerIntCtrl_init(uint8_t timerID, uint32_t periode_us, uint8_t priority){
uint32_t    loadVal;

    // Enable peripherals:
    SysCtlPeripheralEnable(SYSCTL_PERIPH_TIMER0);       // enable Timer0

    // Check if the peripheral access is enabled. (Wait for Timerx module to become ready)
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_TIMER0)){ }

    // Configure the 32-bit periodic timer.
    TimerConfigure(TIMER0_BASE, TIMER_CFG_PERIODIC);                   // set timer0 as a full-width periodic timer


    loadVal = ((g_ui32SysClock/1000000) * periode_us);

    TimerLoadSet(TIMER0_BASE, TIMER_A, loadVal);                // set timer0,A load value

    priority = priority<<5;

    // Setup the interrupt for the timer timeouts.
    IntPrioritySet(INT_TIMER0A, priority);                  // set interrupt priority for timer0A
    IntEnable(INT_TIMER0A);                                     // enable timer0A interrupt
    TimerIntEnable(TIMER0_BASE, TIMER_TIMA_TIMEOUT);            // enable timer interrupt source: timeout of timer0,A

    // Enable the timers.
    TimerEnable(TIMER0_BASE, TIMER_A);                      // enable timer0,A (timer is not split)



    return;
}

