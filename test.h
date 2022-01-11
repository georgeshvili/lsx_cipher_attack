//
//  test.h
//  lsx_cipher_attack
//
//  Created by Георгий Джаниашвили on 22/12/2021.
//  Copyright © 2021 Георгий Джаниашвили. All rights reserved.
//

#ifndef test_h
#define test_h

#include <stdio.h>
#include <iostream>
#include "lsx_cipher_attack.h"
#include "lsx_cipher.h"
#include "utilities.h"

class Test {
    
public:
    
    static void test_cipher_20bit_3r()
    {
        LSX_cipher lsx(20,5,1,0);
        std::vector<int> plain_block = {0xc,0x7,0xd,0x5,0x8};
        
        std::cout << "P ";
        for(auto i : plain_block)
            std::cout << i << ' ';
        std::cout << std::endl;
        std::cout << std::endl;
        
        std::cout << "s_box "; lsx.print_s_box(); std::cout << std::endl;
        std::cout << "s_box_inv "; lsx.print_inv_s_box(); std::cout << std::endl;
        std::cout << "l_table "; std::cout << std::endl; lsx.print_l_table(); std::cout << std::endl;
        std::cout << "l_table_inv "; std::cout << std::endl; lsx.print_l_table_inv(); std::cout << std::endl;
        std::cout << "K "; std::cout << std::endl; lsx.print_key_list(); std::cout << std::endl;
        
        
        std::vector<int> cipher_block;
        cipher_block = lsx.encrypt(plain_block);
        std::cout << "Y ";
        for(auto i : cipher_block)
            std::cout << i << ' ';
        std::cout << std::endl << std::endl;
        cipher_block = lsx.decrypt(cipher_block);
        std::cout << "P ";
        for(auto i : cipher_block)
            std::cout << i << ' ';
        std::cout << std::endl << std::endl;
    }
    
    static void test_cipher_20bit_3r_attack()
    {
        LSX_cipher lsx(20,5,1,0);
        LSX_cipher_attack lsx_attack(lsx);
        lsx_attack.init(12);
        lsx_attack.s_recovery();
        
        std::cout << "s_box "; lsx.print_s_box(); std::cout << std::endl;
        std::cout << "s_box_inv "; lsx.print_inv_s_box(); std::cout << std::endl;
        std::cout << "l_table "; std::cout << std::endl; lsx.print_l_table(); std::cout << std::endl;
        std::cout << "l_table_inv "; std::cout << std::endl; lsx.print_l_table_inv(); std::cout << std::endl;
        std::cout << "K "; std::cout << std::endl; lsx.print_key_list(); std::cout << std::endl;
        
        std::cout << "new_s_box ";
        lsx_attack.print_new_s_box();
        std::cout << std::endl;
        Utilities::calculate_DDT(lsx_attack.get_new_s_box());
        
        std::cout << '\n';
        std::cout << "////////////////";
        std::cout << '\n';
        std::cout << '\n';

        std::cout << "s_box ";
        lsx.print_s_box();
        std::cout << std::endl;
        Utilities::calculate_DDT(lsx.get_s_box());
    }
    
    static void test_cipher_nbit_2qr(int n, int l, int q)
    {
        LSX_cipher lsx(n,l,q,1);
        std::vector<int> plain_block = lsx.random_plain_block();
        for(auto i : plain_block)
            std::cout << i << ' ';
        std::cout << std::endl;
        std::vector<int> cipher_block;
        cipher_block = lsx.encrypt(plain_block);
        for(auto i : cipher_block)
            std::cout << i << ' ';
        std::cout << std::endl;
        cipher_block = lsx.decrypt(cipher_block);
        for(auto i : cipher_block)
            std::cout << i << ' ';
        std::cout << std::endl;
    }
    
    static void test_cipher_attack(int n, int l, int q)
    {
        LSX_cipher lsx(n,l,q,1);
         
        LSX_cipher_attack lsx_attack(lsx);
        lsx_attack.init(12);
        lsx_attack.s_recovery();

        std::cout << "s_box "; lsx.print_s_box(); std::cout << std::endl;
        std::cout << "s_box_inv "; lsx.print_inv_s_box(); std::cout << std::endl;
        std::cout << "l_table "; std::cout << std::endl; lsx.print_l_table(); std::cout << std::endl;
        std::cout << "l_table_inv "; std::cout << std::endl; lsx.print_l_table_inv(); std::cout << std::endl;
        std::cout << "K "; std::cout << std::endl; lsx.print_key_list(); std::cout << std::endl;
        
        std::cout << "new_s_box ";
        lsx_attack.print_new_s_box();
        std::cout << std::endl;
        Utilities::calculate_DDT(lsx_attack.get_new_s_box());
        
        std::cout << '\n';
        std::cout << "////////////////";
        std::cout << '\n';
        std::cout << '\n';

        std::cout << "s_box ";
        lsx.print_s_box();
        std::cout << std::endl;
        Utilities::calculate_DDT(lsx.get_s_box());
    }
    
};


#endif /* test_h */
