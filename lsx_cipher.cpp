//
//  lsx_cipher.cpp
//  lsx_cipher_attack
//
//  Created by Георгий Джаниашвили on 20/12/2021.
//  Copyright © 2021 Георгий Джаниашвили. All rights reserved.
//

#include <stdio.h>
#include <iostream>
#include "lsx_cipher.h"
#include "lsx_cipher_tables.h"

std::random_device rd;
std::mt19937 g(rd());

LSX_cipher::LSX_cipher(){
};

LSX_cipher::LSX_cipher(size_t n, size_t l, size_t q, int k)
{
    n_ = n; l_ = l; q_ = q;
    if(k == 1) {
        create_key();
        create_s_box();
        inverse_s_box();
        create_v();
        create_a();
        create_l_table_over_gf16();
        inverse_l_table();
    }
};

std::vector<int> LSX_cipher::random_plain_block()
{
    std::vector<int> plain_block;
    std::shuffle(std::begin(numbers), std::end(numbers), g);
    for(int i = 0; i < l_; i++) {
        plain_block.push_back(numbers[i]);
    }
    return plain_block;
}

int LSX_cipher::find_div_gf16(int a, int b)
{
    int k;
    for(int i = 0; i < sbox_size_; i++){
        if(gf16[a][i] == b) {
            k = i;
            break;
        }
    }
    return k;
}

std::vector<std::vector<int>> LSX_cipher::gaussian_elimination_gf16(std::vector<std::vector<int>> a)
{
    //upper triangular
    for(int i = 0; i < l_ - 1; i++){
        for(int j = i+1; j < l_; j++){
            int c = find_div_gf16(a[i][i], a[j][i]);
            for(int k = 0; k < 2 * l_; k++){
                a[j][k] = gf16[c][a[i][k]] ^ a[j][k];
            }
        }
    }
    
    //lower and upper triangular matrix
    for(int i = l_ - 1; i > 0; i--){
        for(int j = i - 1; j >= 0; j--){
            int c = find_div_gf16(a[i][i], a[j][i]);
            for(int k = 2 * l_ - 1; k > 0; k--){
                    a[j][k] = gf16[c][a[i][k]] ^ a[j][k];
            }
        }
    }
    
    //identity matrix
    for(int i = 0; i < l_; i++){
        int c = find_div_gf16(a[i][i], 1);
        for(int j = 0; j < 2 * l_; j++){
            a[i][j] = gf16[c][a[i][j]];
        }
    }
    
    return a;
    
}

int LSX_cipher::expo_gf16(int number, int power)
{
    if(power == 1){
        return number;
    }
    else {
        int number_tmp = number;
        for(int i = 0; i < power - 1; i ++){
            number_tmp = gf16[number][number_tmp];
        }
        number = number_tmp;
    }
    return number;
}

std::vector<int> durstenfeld(int size){

    std::vector<int> arr;
    for(int i = 0; i < size; i++) {
            arr.push_back(i);
    }

    std::random_device rd;
    std::mt19937 g(rd());

    for(int i = arr.size() - 1; i >= 0; i--) {
        std::uniform_int_distribution<int> gen(0, i); // uniform, unbiased
        int j = gen(g);
        
        int tmp = arr[j];
        arr[j] = arr[i];
        arr[i] = tmp;
    }
    return arr;
}

std::vector<int> fisher_Yates(int size){

    std::vector<int> arr;
    for(int i = 0; i < size; i++) {
            arr.push_back(i);
    }

    std::vector<int> res;
    std::random_device rd;
    std::mt19937 g(rd());

    for(int i = arr.size() - 1; i >= 0; i--) {
        std::uniform_int_distribution<int> gen(0, i); // uniform, unbiased
        int j = gen(g);
        res.push_back(arr[j]);
        arr.erase(arr.begin() + j);
    }
    return res;
}

void LSX_cipher::create_s_box ()
{
    std::vector<int> s_box_;
    std::shuffle(std::begin(numbers), std::end(numbers), g);
    for(int i = 0; i < sbox_size_; i++) {
        s_box_.push_back(numbers[i]);
    }
    s_box = s_box_;
}

void LSX_cipher::inverse_s_box ()
{
    std::vector<int> s_box_inv_;
    for(int i = 0; i < sbox_size_; i++) {
        for(int j = 0; j < sbox_size_; j++) {
            if(s_box[j] == i) {
                s_box_inv_.push_back(j);
            }
        }
    }
    s_box_inv = s_box_inv_;
}

void LSX_cipher::create_key()
{
    std::vector<std::vector<int>> key_list_;
    for(int i = 0; i < 2 * q_ + 1; i++){
        std::vector<int> tmp;
        for(int j = 0; j < l_; j++) {
            std::uniform_int_distribution<int> gen(0, sbox_size_ - 1); // uniform, unbiased
            int r = gen(g);
            tmp.push_back(r);
        }
        key_list_.push_back(tmp);
    }
    key_list = key_list_;
}

void LSX_cipher::create_v ()
{

    for(int i = 0; i < 2 * l_; i++) {
        std::uniform_int_distribution<int> gen(1, sbox_size_ - 1); // uniform, unbiased
        int r = gen(g);
        v.push_back(r);
    }
}

void LSX_cipher::create_a ()
{
    std::shuffle(std::begin(numbers), std::end(numbers), g);
    for(int i = 0; i < 2 * l_; i++) {
        a.push_back(numbers[i]);
    }
}

void LSX_cipher::create_l_table_over_gf16()
{
    std::vector<std::vector<int>> G;
    for(int i = 0; i < l_; i++){
        std::vector<int> tmp;
        for(int j = 0; j < 2 * l_; j++){
            if(i == 0) {
                tmp.push_back(v[j]);
            }
            else {
                tmp.push_back(gf16[v[j]][expo_gf16(a[j], i)]);
            }
        }
        G.push_back(tmp);
    }
    
    G = gaussian_elimination_gf16(G);
    
    //заполняем L
    std::vector<std::vector<int>> l_table_;
    for(int i = 0; i < l_; i++){
        std::vector<int> tmp;
        for(int j = 0; j < l_; j++){
            tmp.push_back(G[i][j + l_]);
        }
        l_table_.push_back(tmp);
    }
    l_table = l_table_;
}

void LSX_cipher::inverse_l_table()
{
    std::vector<std::vector<int>> inv(l_, std::vector<int>(2 * l_, 0));
    //init fill
    for(int i = 0; i < l_; i++){
        for(int j = 0; j < l_; j++){
            inv[i][j] = l_table[i][j];
        }
    }
    for(int i = 0; i < l_; i++){
        inv[i][i + l_] = 1;
    }
    //left and right upper triangular
    for(int i = 0 ; i < l_ - 1; i++){
        int above = find_div_gf16(inv[i][i], 1);
        for(int z = 0; z < 2 * l_; z++)
            inv[i][z] = gf16[inv[i][z]][above];
        for(int j = i+1; j < l_; j++){
            int below = inv[j][i];
            for(int k = 0; k < 2 * l_; k++){
                int tmp = gf16[inv[i][k]][below];
                inv[j][k] ^= tmp;

            }
        }
    }
    //left identity matrix right inverse l_table
    for(int i = l_ - 1 ; i > 0; i--){
        int below = find_div_gf16(inv[i][i], 1);
        for(int z = 2 * l_ - 1; z > 0; z--)
            inv[i][z] = gf16[inv[i][z]][below];
        for(int j = i - 1; j >= 0; j--){
            int above = inv[j][i];
            for(int k = 2 * l_ - 1; k > 0; k--){
                int tmp = gf16[inv[i][k]][above];
                inv[j][k] ^= tmp;

            }
        }
    }
    std::vector<std::vector<int>> l_table_inv_;
    for(int i = 0; i < l_; i++){
        std::vector<int> tmp;
        for(int j = 0; j < l_; j++){
            tmp.push_back(inv[i][j + l_]);
        }
        l_table_inv_.push_back(tmp);
    }
    l_table_inv = l_table_inv_;
}

std::vector<int> LSX_cipher::s_box_sub (std::vector<int> x)
{
    std::vector<int> x_after_s;
    
    for(int i = 0; i < l_; i++){
        for(int  j = 0; j < sbox_size_; j++){
            if(x[i] == j) {
                x_after_s.push_back(s_box[j]);
            }
        }
    }
    return x_after_s;
}

std::vector<int> LSX_cipher::s_box_sub_inv (std::vector<int> x)
{
    std::vector<int> x_after_s;
    
    for(int i = 0; i < l_; i++){
        for(int  j = 0; j < sbox_size_; j++){
            if(x[i] == j) {
                x_after_s.push_back(s_box_inv[j]);
            }
        }
    }
    return x_after_s;
}

std::vector<int> LSX_cipher::xor_x_and_key(std::vector<int> x, size_t round)
{
    for(int i = 0; i < l_; i++){
        x[i] ^= key_list[round][i];
    }
    return x;
}

std::vector<int> LSX_cipher::mul_matrix(std::vector<int> x)
{
    //init
    std::vector<int> x_after_l_box;
    for(int i = 0; i < l_; i++) {
        x_after_l_box.push_back(0);
    }

    for(int  i = 0; i < l_; i++) {
        for(int j = 0; j < l_; j++){
            int k = gf16[x[j]][l_table[i][j]];
            x_after_l_box[i] = x_after_l_box[i] ^ k;
        }
    }

    return x_after_l_box;
}

std::vector<int> LSX_cipher::mul_matrix_inv(std::vector<int> x)
{
    //init
    std::vector<int> x_after_l_box;
    for(int i = 0; i < l_; i++) {
        x_after_l_box.push_back(0);
    }

    for(int  i = 0; i < l_; i++) {
        for(int j = 0; j < l_; j++){
            int k = gf16[x[j]][l_table_inv[i][j]];
            x_after_l_box[i] = x_after_l_box[i] ^ k;
        }
    }

    return x_after_l_box;
}

std::vector<int> LSX_cipher::encryptBlock(std::vector<int> block)
{
    for (int i = 0; i < 2 * q_ + 1; i++)
    {
        block = xor_x_and_key(block, i);
        block = mul_matrix(block);
        block = s_box_sub(block);
    }
    return block;
}

std::vector<int> LSX_cipher::decryptBlock(std::vector<int> block)
{
    for(int i = 2 * q_; i >= 0; i--)
    {
        block = s_box_sub_inv(block);
        block = mul_matrix_inv(block);
        block = xor_x_and_key(block, i);
    }
    return block;
}

std::vector<int> LSX_cipher::encrypt(std::vector<int> plain_block)
{
    plain_block = encryptBlock(plain_block);
    return plain_block;
}

std::vector<int> LSX_cipher::decrypt(std::vector<int> cipher_block)
{
    cipher_block = decryptBlock(cipher_block);
    return cipher_block;
}

void LSX_cipher::print_s_box()
{
    for(auto i : s_box) {
        std::cout << i << ' ';
    }
    std::cout << '\n';
}

void LSX_cipher::print_inv_s_box()
{
    for(auto i : s_box_inv) {
        std::cout << i << ' ';
    }
    std::cout << '\n';
}

void LSX_cipher::print_l_table()
{
    for(auto row : l_table) {
        for(auto i : row) {
            std::cout << i << ' ';
        }
        std::cout << '\n';
    }
}

void LSX_cipher::print_l_table_inv()
{
    for(auto row : l_table_inv) {
        for(auto i : row) {
            std::cout << i << ' ';
        }
        std::cout << '\n';
    }
};

void LSX_cipher::print_key_list()
{
    for(auto row : key_list) {
        for(auto i : row) {
            std::cout << i << ' ';
        }
        std::cout << '\n';
    }
};

std::vector<int> LSX_cipher::get_s_box()
{
    return s_box;
}

std::vector<std::vector<int>> LSX_cipher::get_l_table()
{
    return l_table;
}

std::vector<std::vector<int>> LSX_cipher::get_l_table_inv()
{
    return l_table_inv;
}

size_t LSX_cipher::get_cipher_size()
{
    return n_;
}

size_t LSX_cipher::get_sbox_size(){
    return sbox_size_;
};
