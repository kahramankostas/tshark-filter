
# coding: utf-8

# # automates the tshark filter rules within a CSV file using python.

# In[1]:


import os
import pandas as pd


# ##   The "filter.csv" file contains 4 different categories.
# ## the most necessary here are "File Name" and "Rule".
# ## It may be wise to use Category	and Sub-category options if you are going to apply multiple rules to the same PCAP file.
# 

# In[3]:


df = pd.read_csv( "filter_rules.csv")
df.head()


# In[4]:


name=df['File Name']
rule=df['Rule']
cat=df['Category']
subcat=df['Sub-category']


# In[5]:


for i in range(len(name)):
    add=str(cat[i])+"@"+str(subcat[i])+"_"
    add=add.replace(" ","_")
    
    #packets that meet with the filter rules
    command='tshark -Y \"'+str(rule[i])+"\" -r "+str(name[i])+" -w filtered_"+add+str(name[i])
    os.system(command)
    #packets that do not meet the filter rules 
    command='tshark -Y \"!('+str(rule[i])+")\" -r "+str(name[i])+" -w other_"+add+str(name[i])
    os.system(command)

    

