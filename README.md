# Pre-trained Model-based Automated Software Vulnerability Repair: How Far are We?

## How to set up the running environment

Please run the following commands to install the necessary packages for running the replication package.

```
pip install pipreqs
pipreqs /the/root/entry --encoding=utf-8 --force
pip install -r requirements.txt 
```

## How to run the replication package

We created the folders according to the RQs we propose in our paper.

Each sub-folder contains a file named run.py. It contains the shell commands used for training and testing the corresponding model. To replicate the results of our paper, run the following commands:

```
cd /the entry you want
python run.py
```

If you want to reproduce the result rather than train the model from the scratch, you may access this link [vulnerability](https://smailnjueducn-my.sharepoint.com/:f:/g/personal/201250070_smail_nju_edu_cn/EicUcUSD9wdJvHlBmHb4gqsBdTUG9RgvQXS8AVUS9-t12A?e=E0pf32)  to download the binary files we trained.

Noticed that the file named "bugfix_train.py" exceeds the file size limit of GitHub, you may also need to refer to the link above to download the data.

## SCAN

SCAN is an abstraction tool we developed and employed in the experiment. We have already provided the jar executable file in the "data" folder. To run the abstraction, please run the following command.

```
java -jar cabs.jar source_input.c target_input.c source_output.c target_output.c map
```

Specific examples can be viewed in trans.py in the data folder.

The source code of SCAN is also available on GitHub https://github.com/QuanjunZhang/SCAN

