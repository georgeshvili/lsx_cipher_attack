//
//  main.cpp
//  lsx_cipher_attack
//
//  Created by Георгий Джаниашвили on 19/12/2021.
//  Copyright © 2021 Георгий Джаниашвили. All rights reserved.
//

#include "test.h"

int main(int argc, const char * argv[]) {
    
    //Test::test_cipher_20bit_3r();
    Test::test_cipher_attack(32, 8, 1);
    //Test::test_cipher_20bit_3r_attack();
    
    return 0;
}
