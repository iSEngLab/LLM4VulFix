import os
if __name__ =="__main__":
    os.system("python unixcoder_main.py --output_dir=./saved_models --split 0 --model_name=0.bin --do_nofinetune --test_data_file=../data/fine_tune_data/cve_fixes_test.csv --encoder_block_size 512 --decoder_block_size 256 --eval_batch_size 1 --n_gpu 1")
    splits = [0.2,0.4,0.6,0.8]
    for i in splits:
        os.system("python unixcoder_main.py --output_dir=./saved_models --split {} --model_name={}.bin --do_train --train_data_file=../data/fine_tune_data/cve_fixes_train_{}.csv --eval_data_file=../data/fine_tune_data/cve_fixes_val_{}.csv --test_data_file=../data/fine_tune_data/cve_fixes_test.csv --epochs 40 --encoder_block_size 512 --decoder_block_size 256 --train_batch_size 8 --eval_batch_size 8 --learning_rate 2e-5 --max_grad_norm 1.0 --n_gpu 1 --evaluate_during_training --seed 123456  2>&1 | tee train.log".format(i,i,i,i))
        os.system("python unixcoder_main.py --output_dir=./saved_models --split {} --model_name={}.bin --do_test --test_data_file=../data/fine_tune_data/cve_fixes_test.csv --encoder_block_size 512 --decoder_block_size 256 --eval_batch_size 1 --n_gpu 1".format(i,i))
