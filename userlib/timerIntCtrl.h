/*
 * timer.h
 *
 *  Created on: 07.11.2019
 *      Author: bboeck
 */

#ifndef TIMERINTCTRL_H_
#define TIMERINTCTRL_H_



    /** @brief setup timer0A with interrupt
    * @param  timerID       : 0
    * @param  periode_us    : clock periode [us]
    * @param  priority      : interrupt priority (0...7), 7 is lowest
    */
    void timerIntCtrl_init(uint8_t timerID, uint32_t periode_us, uint8_t priority);



#endif /* TIMERINTCTRL_H_ */
