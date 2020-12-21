# tshark-filter

## automates the tshark filter rules within a CSV file using python.


```python
import os
import pandas as pd
```

###   The "filter.csv" file contains 4 different categories.
### the most necessary here are "File Name" and "Rule".
### It may be wise to use Category	and Sub-category options if you are going to apply multiple rules to the same PCAP file.



```python
df = pd.read_csv( "filter_rules.csv")
df.head()
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>No</th>
      <th>File Name</th>
      <th>Category</th>
      <th>Sub-category</th>
      <th>Rule</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>1</td>
      <td>1.pcap</td>
      <td>a</td>
      <td>x</td>
      <td>ip.dst == 111.11.111.11</td>
    </tr>
    <tr>
      <th>1</th>
      <td>2</td>
      <td>1.pcap</td>
      <td>a</td>
      <td>x</td>
      <td>ip.dst == 111.11.111.12</td>
    </tr>
    <tr>
      <th>2</th>
      <td>3</td>
      <td>1.pcap</td>
      <td>a</td>
      <td>x</td>
      <td>ip.dst == 111.11.111.13</td>
    </tr>
    <tr>
      <th>3</th>
      <td>4</td>
      <td>1.pcap</td>
      <td>b</td>
      <td>w</td>
      <td>ip.dst == 111.11.111.14</td>
    </tr>
    <tr>
      <th>4</th>
      <td>5</td>
      <td>1.pcap</td>
      <td>b</td>
      <td>w</td>
      <td>ip.dst == 111.11.111.15</td>
    </tr>
  </tbody>
</table>
</div>




```python
name=df['File Name']
rule=df['Rule']
cat=df['Category']
subcat=df['Sub-category']
```


```python
for i in range(len(name)):
    add=str(cat[i])+"@"+str(subcat[i])+"_"
    add=add.replace(" ","_")
    
    #packets that meet with the filter rules
    command='tshark -Y \"'+str(rule[i])+"\" -r "+str(name[i])+" -w filtered_"+add+str(name[i])
    os.system(command)
    #packets that do not meet the filter rules 
    command='tshark -Y \"!('+str(rule[i])+")\" -r "+str(name[i])+" -w other_"+add+str(name[i])
    os.system(command)

    
```
