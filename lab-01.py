#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 27 13:10:11 2020

@author: krishna
"""

import pandas as pd
list1=[]
with open('numbers','r') as file:
    list1.append(file.readlines())
    
list2=list1[0]
list2=pd.DataFrame(list2)
list3=list2[0].value_counts()
print(list3)

with open('numbers_occurenece','w') as file1:
    for zip(list3.index,list3[0]) in list3:
        occurence=list3[0]
        number=list3.index
        file1.write('The number ',number, 'appeared ',occurence, 'times')



        
    

    
    
    
