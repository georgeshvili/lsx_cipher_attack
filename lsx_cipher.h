//
//  lsx_cipher.h
//  lsx_cipher_attack
//
//  Created by Георгий Джаниашвили on 19/12/2021.
//  Copyright © 2021 Георгий Джаниашвили. All rights reserved.
//

#ifndef lsx_cipher_h
#define lsx_cipher_h

#include <stdio.h>
#include <random>

class LSX_cipher {

    size_t n_;
    size_t l_;
    size_t m_ = 4;
    size_t q_;
    static const size_t sbox_size_ = 16;
    
    private:
        
    static std::vector<int> s_box;
    static std::vector<int> s_box_inv;
    static std::vector<std::vector<int>> key_list;
    std::vector<int> v;
    std::vector<int> a;
    static std::vector<std::vector<int>> l_table;
    static std::vector<std::vector<int>> l_table_inv;
    
    //find inverse element, a * a^(-1) = b
    int find_div_gf16(int a, int b);
    std::vector<std::vector<int>> gaussian_elimination_gf16(std::vector<std::vector<int>> a);
    int expo_gf16(int number, int power);
    
    std::vector<int> durstenfeld(int size);
    std::vector<int> fisher_Yates(int size);
    
    void create_s_box();
    void inverse_s_box();
    void create_key();
    void create_v();
    void create_a();
    void create_l_table_over_gf16();
    void inverse_l_table();
    
    std::vector<int> s_box_sub (std::vector<int> x);
    std::vector<int> s_box_sub_inv (std::vector<int> x);
    std::vector<int> xor_x_and_key(std::vector<int> x, size_t round);
    std::vector<int> mul_matrix (std::vector<int> x);
    std::vector<int> mul_matrix_inv (std::vector<int> x);
    std::vector<int> encryptBlock(std::vector<int> block);
    std::vector<int> decryptBlock(std::vector<int> block);

    public:

    LSX_cipher();
    LSX_cipher(size_t n, size_t l, size_t q, int k);
    std::vector<int> random_plain_block();
    
    std::vector<int> encrypt(std::vector<int> plain_block);
    std::vector<int> decrypt(std::vector<int> cipher_block);
    
    void print_s_box();
    void print_inv_s_box();
    void print_l_table();
    void print_l_table_inv();
    void print_key_list();
    
    std::vector<int> get_s_box();
    std::vector<std::vector<int>> get_l_table();
    std::vector<std::vector<int>> get_l_table_inv();
    size_t get_cipher_size();
    size_t get_sbox_size();
    
};

#endif /* lsx_cipher_h */
