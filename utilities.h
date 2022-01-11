//
//  utilities.hpp
//  lsx_cipher_attack
//
//  Created by Георгий Джаниашвили on 20/12/2021.
//  Copyright © 2021 Георгий Джаниашвили. All rights reserved.
//

#ifndef utilities_h
#define utilities_h

#include <stdio.h>
#include <map>

class Utilities {
    
    public:
        
    static void calculate_DDT(std::vector<int> box){
            
        size_t n = box.size();
        std::vector<std::vector<int>> DDT(n, std::vector<int>(n,0));
        for(int a = 0; a < n; a++) {
            for(int d1 = 0; d1 < n; d1++) {
                int d2 = box[a] ^ box[a ^ d1];
                 DDT[d1][d2] += 1;
            }
        }
        
        std::map<int, int> counts;
    
        for (auto row : DDT ) {
            for (auto s : row ) {
                if (counts.count(s)) {
                    counts[s]++;
                } else {
                    counts[s] = 1;
                }
            }
        }
            
        for(auto i : counts) {
            std::cout << (int) i.first << ' ' << (int) i.second << '\n';
        }
    }
        
};

#endif /* utilities_h */
