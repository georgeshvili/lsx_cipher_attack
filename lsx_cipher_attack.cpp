//
//  lsx_cipher_attack.cpp
//  lsx_cipher_attack
//
//  Created by Георгий Джаниашвили on 20/12/2021.
//  Copyright © 2021 Георгий Джаниашвили. All rights reserved.
//

#include <stdio.h>
#include <iostream>
#include "lsx_cipher_attack.h"

LSX_cipher_attack::LSX_cipher_attack(LSX_cipher lsx)
{
    lsx_ = lsx;
};

std::vector<std::vector<int>> LSX_cipher_attack::create_V_of_dim12 (int C, int block_size)
{
    std::vector<std::vector<int>> V;

    for(int i = 0; i < lsx_.get_sbox_size(); i++) {
        for(int j = 0; j < lsx_.get_sbox_size(); j++) {
            for(int k = 0; k < lsx_.get_sbox_size(); k++) {
                std::vector<int> x;
                x.push_back(i); x.push_back(j); x.push_back(k);
                for(int tmp = 0; tmp < block_size - 3; tmp++) {
                    x.push_back(C);
                }
                V.push_back(x);
            }
        }
    }
    return V;
}

std::vector<std::vector<int>> LSX_cipher_attack::create_V_of_dim16 (int C, int block_size)
{
    std::vector<std::vector<int>> V;

    for(int i = 0; i < lsx_.get_sbox_size(); i++) {
        for(int j = 0; j < lsx_.get_sbox_size(); j++) {
            for(int k = 0; k < lsx_.get_sbox_size(); k++) {
                for(int z = 0; z < lsx_.get_sbox_size(); z++) {
                    std::vector<int> x;
                    x.push_back(i); x.push_back(j); x.push_back(k); x.push_back(z);
                    for(int tmp = 0; tmp < block_size - 4; tmp++) {
                        x.push_back(C);
                    }
                    V.push_back(x);
                }
            }
        }
    }
    return V;
}

std::vector<std::vector<int>> LSX_cipher_attack::create_V_of_dim20 (int C, int block_size)
{
    std::vector<std::vector<int>> V;

    for(int i = 0; i < lsx_.get_sbox_size(); i++) {
        for(int j = 0; j < lsx_.get_sbox_size(); j++) {
            for(int k = 0; k < lsx_.get_sbox_size(); k++) {
                for(int z = 0; z < lsx_.get_sbox_size(); z++) {
                    for(int h = 0; h < lsx_.get_sbox_size(); h++) {
                        std::vector<int> x;
                        x.push_back(i); x.push_back(j); x.push_back(k);
                        x.push_back(z); x.push_back(h);
                        for(int tmp = 0; tmp < block_size - 5; tmp++) {
                            x.push_back(C);
                        }
                        V.push_back(x);
                    }
                }
            }
        }
    }
    return V;
}

std::vector<std::vector<int>> LSX_cipher_attack::create_V_of_dim28 (int C, int block_size)
{
    std::vector<std::vector<int>> V;

    for(int i = 0; i < lsx_.get_sbox_size(); i++) {
        for(int j = 0; j < lsx_.get_sbox_size(); j++) {
            for(int k = 0; k < lsx_.get_sbox_size(); k++) {
                for(int z = 0; z < lsx_.get_sbox_size(); z++) {
                    for(int h = 0; h < lsx_.get_sbox_size(); h++) {
                        for(int u = 0; u < lsx_.get_sbox_size(); u++) {
                            for(int e = 0; e < lsx_.get_sbox_size(); e++) {
                                std::vector<int> x;
                                x.push_back(i); x.push_back(j); x.push_back(k);
                                x.push_back(z); x.push_back(h); x.push_back(u);
                                x.push_back(e);
                                for(int tmp = 0; tmp < block_size - 7; tmp++) {
                                    x.push_back(C);
                                }
                                V.push_back(x);
                            }
                        }
                    }
                }
            }
        }
    }
    return V;
}

void LSX_cipher_attack::init (int size_of_dim)
{
    size_of_dim_ = size_of_dim;
    std::vector<std::vector<std::vector<int>>> plain_packs;
    if(size_of_dim == 12) {
        for(int i = 0; i < lsx_.get_sbox_size(); i++) {
            plain_packs.push_back(create_V_of_dim12(i, lsx_.get_cipher_size()));
        }
    } else if (size_of_dim == 16) {
        for(int i = 0; i < lsx_.get_sbox_size(); i++) {
            plain_packs.push_back(create_V_of_dim16(i, lsx_.get_cipher_size()));
        }
    } else if (size_of_dim == 20) {
        for(int i = 0; i < lsx_.get_sbox_size(); i++) {
            plain_packs.push_back(create_V_of_dim20(i, lsx_.get_cipher_size()));
        }
    } else if (size_of_dim == 28) {
        for(int i = 0; i < lsx_.get_sbox_size(); i++) {
            plain_packs.push_back(create_V_of_dim28(i, lsx_.get_cipher_size()));
        }
    }
    else {
        std::cout << "err" << std::endl;
    }
    for(int i = 0; i < lsx_.get_sbox_size(); i++) {
        std::vector<std::vector<int>> ctt;
        for(int j = 0; j < std::pow(lsx_.get_sbox_size(), size_of_dim_ / 4); j++) {
            std::vector<int> x = lsx_.encrypt(plain_packs[i][j]);
            ctt.push_back(x);
        }
        cipher_packs_.push_back(ctt);
    }
}

void LSX_cipher_attack::s_recovery ()
{
    int column_id = 0;
    std::vector<std::vector<int>> columns(lsx_.get_sbox_size(), std::vector<int>(std::pow(lsx_.get_sbox_size(), size_of_dim_ / 4),0));
    for(int i = 0; i < lsx_.get_sbox_size(); i++) {
        for(int j = 0; j < std::pow(lsx_.get_sbox_size(), size_of_dim_ / 4); j++) {
            columns[i][j] = cipher_packs_[i][j][column_id];
        }
    }

    std::vector<std::vector<int>> equations(lsx_.get_sbox_size(), std::vector<int>(lsx_.get_sbox_size(),0));
    for(int j = 0; j < lsx_.get_sbox_size(); j++) {
        for(int k = 0; k < std::pow(lsx_.get_sbox_size(), size_of_dim_ / 4); k++) {
            int v = columns[j][k];
            equations[j][v]+=1;
        }
    }

    std::vector<std::vector<int>> equations_mod2(lsx_.get_sbox_size(), std::vector<int>(lsx_.get_sbox_size(),0));
    for(int j = 0; j < lsx_.get_sbox_size(); j++) {
        for(int k = 0; k < lsx_.get_sbox_size(); k++) {
            equations_mod2[j][k] = equations[j][k] % 2;
        }
    }

    std::vector<std::vector<int>> system = equations_mod2;
    
    for(auto row : system) {
        for(auto i : row) {
            std::cout << i << ' ';
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;

    for(int i = 0; i < lsx_.get_sbox_size(); i++) {
        int lead_one = 0;
        for(int s = i; s < lsx_.get_sbox_size(); s++) {
            if(system[s][i] == 1) {
                lead_one = 1;
                system[s].swap(system[i]);
                break;
            }
        }
        if(lead_one == 0) {
            continue;
        }
        for(int j = i+1; j < lsx_.get_sbox_size(); j++) {
            if(system[j][i] == 1) {
                for(int p = i; p < lsx_.get_sbox_size(); p++) {
                    system[j][p] ^= system[i][p];
                }
            }
        }
    }

    int c = 0;
    int count_vec = 0;
    for(int i = 0; i < lsx_.get_sbox_size(); i++){
        for(int j = 0; j < lsx_.get_sbox_size(); j++){
            if(system[i][j] == 1)
                c = 1;
            std::cout << system[i][j] << ' ';
        }
        if(c == 0) {
            count_vec++;
        }
        c = 0;
        std::cout << std::endl;
    }
    std::cout << std::endl;

    std::vector<int> new_sbox(lsx_.get_sbox_size() - count_vec, 0);
    
    if(count_vec == 5) {
        new_sbox.push_back(9); new_sbox.push_back(8); new_sbox.push_back(4);
        new_sbox.push_back(2); new_sbox.push_back(1);
    }
    if(count_vec == 4) {
        new_sbox.push_back(8); new_sbox.push_back(4);
        new_sbox.push_back(2); new_sbox.push_back(1);
    }

    for(int i = lsx_.get_sbox_size() - 1 - count_vec; i >= 0; i--) {
        int xor_sum = 0;
        for(int j = i + 1; j < lsx_.get_sbox_size(); j++){
            if(system[i][j]) {
                xor_sum ^= new_sbox[j];
            }
        }
        new_sbox[i] = xor_sum;
    }
    new_sbox_ = new_sbox;
}

void LSX_cipher_attack::print_new_s_box()
{
    for(auto i : new_sbox_) {
        std::cout << i << ' ';
    }
    std::cout << '\n';
}

std::vector<int> LSX_cipher_attack::get_new_s_box()
{
    return new_sbox_;
}
