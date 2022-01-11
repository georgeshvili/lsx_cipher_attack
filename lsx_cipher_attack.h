//
//  lsx_cipher_attack.h
//  lsx_cipher_attack
//
//  Created by Георгий Джаниашвили on 20/12/2021.
//  Copyright © 2021 Георгий Джаниашвили. All rights reserved.
//

#ifndef lsx_cipher_attack_h
#define lsx_cipher_attack_h

#include <stdio.h>
#include "lsx_cipher.h"

class LSX_cipher_attack {
    
    private:
    
    int size_of_dim_;
    std::vector<std::vector<std::vector<int>>> cipher_packs_;
    std::vector<int> new_sbox_;
    LSX_cipher lsx_;
    
    std::vector<std::vector<int>> create_V_of_dim12 (int C, int block_size);
    std::vector<std::vector<int>> create_V_of_dim16 (int C, int block_size);
    std::vector<std::vector<int>> create_V_of_dim20 (int C, int block_size);
    std::vector<std::vector<int>> create_V_of_dim28 (int C, int block_size);
    
    public:
        
    LSX_cipher_attack(LSX_cipher lsx);
    
    void init (int size_of_dim);
    void s_recovery ();
    
    void print_new_s_box();
    std::vector<int> get_new_s_box();
};

#endif /* lsx_cipher_attack_h */
