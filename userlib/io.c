//*****************************************************************************
//
// io.c - I/O routines
//
//*****************************************************************************
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"
#include "inc/hw_pwm.h"
#include "inc/hw_types.h"
#include "driverlib/gpio.h"
#include "driverlib/sysctl.h"
#include "driverlib/rom.h"
#include "driverlib/rom_map.h"      // allows the use of the MAP_ prefix
#include "drivers/pinout.h"

#include "CFAF128128B0145T/CFAF128128B0145T.h"      // Display

#include "io.h"

// The system clock speed.
extern uint32_t g_ui32SysClock;



int     io_ledState;
char    textData[TEXT_MAX_NB_OF_TEXTES][TEXT_MAX_NB_OF_CHARS+1];
rgb_t   rgbLED;


//*****************************************************************************
//
// Initialize IO
//
//*****************************************************************************
void io_init(void)
{
    rgb_t rgbLocal;


    PinoutSet(true, false);

    // Enable peripherals:
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPION);        // enable GPIO Port N (LED1, LED2)

    // Check if the peripheral access is enabled. (Wait for GPIOx module to become ready)
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_GPION)){ }


    // Set pin LED1_PIN at port LED1_PORT_BASE as output, SW controlled.
    ROM_GPIOPinTypeGPIOOutput(LED1_PORT_BASE, LED1_PIN);

    // switch LED off (0)
    ROM_GPIOPinWrite(LED1_PORT_BASE, LED1_PIN, 0);

    // Set pin LED2_PIN at port LED2_PORT_BASE as output, SW controlled.
    ROM_GPIOPinTypeGPIOOutput(LED2_PORT_BASE, LED2_PIN);

    // switch LED off (0)
    ROM_GPIOPinWrite(LED2_PORT_BASE, LED2_PIN, 0);




    // Display
    // *******
    // Init Display module
    CFAF128128B0145T_init(BOOSTER_PACK_POSITION, g_ui32SysClock, 20000000);




    // Initialize Dummy I/Os

    // LED control test
    io_ledSetState(0);


    // texts
    io_textSet(0, "Max");         // first name
    io_textSet(1, "Mustermann");  // last name
    io_textSet(2, "Tescht");      // userstring


    // RGB LED
    rgbLocal.r = 255;
    rgbLocal.g = 0;
    rgbLocal.b = 0;
    io_ledRGBSet(rgbLocal);

    return;
}



void io_display(uint32_t localIP)
{
    char    localStr[22];
    int     l;


    // Titel                          123456789012345678901
    CFAF128128B0145T_text(0, 20, "  Embedded Webserver ", CFAF128128B0145T_color_white, CFAF128128B0145T_color_black, 1, 1);
    CFAF128128B0145T_text(0, 30, "_____________________", CFAF128128B0145T_color_white, CFAF128128B0145T_color_black, 1, 1);


    // IP info
    sprintf(&localStr[0]," %d.%d.%d.%d", localIP & 0xff, (localIP >> 8) & 0xff, (localIP >> 16) & 0xff, (localIP >> 24) & 0xff);
    l = strlen(&localStr[0]);
    memset(&localStr[l], ' ', 21-l);    // fill with SPACEs
    localStr[21] = '\0';                // terminate string

    switch(localIP){
        case 0xFFFFFFFF:
            //                            123456789012345678901
            CFAF128128B0145T_text(0, 40, "Waiting for LINK ... ", CFAF128128B0145T_color_white, CFAF128128B0145T_color_black, 1, 1);
            break;

        case 0:
            //                            123456789012345678901
            CFAF128128B0145T_text(0, 40, "Waiting for IP ...   ", CFAF128128B0145T_color_white, CFAF128128B0145T_color_black, 1, 1);
            break;

        default:
            //                            123456789012345678901
            CFAF128128B0145T_text(0, 40, "IP-Address:        ", CFAF128128B0145T_color_white, CFAF128128B0145T_color_black, 1, 1);
            CFAF128128B0145T_text(0, 50, localStr, CFAF128128B0145T_color_white, CFAF128128B0145T_color_black, 1, 1);
            break;
    }


    return;
}



int io_ledGetState(void)
{
    return(io_ledState);
}


int io_ledSetState(int state)
{
    io_ledState = state;

    if(state != 0){
        MAP_GPIOPinWrite(LED2_PORT_BASE, LED2_PIN, LED2_PIN);
    }
    else{
        MAP_GPIOPinWrite(LED2_PORT_BASE, LED2_PIN, 0x00);
    }

    return(state);
}





// textID 0 or 1
void io_textGet(int textID, char *pText)
{
    if(textID < TEXT_MAX_NB_OF_TEXTES){
        strcpy(pText, &textData[textID][0]);
    }
    else{
        pText = '\0';   // set empty text
    }
    return;
}


// textID 0 or 1
void io_textSet(int textID, char *pText)
{
    if(textID < TEXT_MAX_NB_OF_TEXTES){
        strcpy(&textData[textID][0], pText);
    }
    return;
}



rgb_t io_ledRGBGet(void)
{
    return(rgbLED);
}


void io_ledRGBSet(rgb_t rgbValue)
{
    rgbLED = rgbValue;

    // Hardware control not yset implemented

    return;
}

