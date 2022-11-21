import os
if __name__ =="__main__":
        i = input()
        os.system(
            "python codet5_main.py --datano {} --output_dir=./saved_models --model_name=model_{}.bin --do_train --train_data_file=../data/fine_tune_data/{}/cve_fixes_train.csv --eval_data_file=../data/fine_tune_data/{}/cve_fixes_val.csv --test_data_file=../data/fine_tune_data/{}/cve_fixes_test.csv --epochs 35 --encoder_block_size 512 --decoder_block_size 256 --train_batch_size 8 --eval_batch_size 8 --learning_rate 2e-5 --max_grad_norm 1.0 --n_gpu 1 --evaluate_during_training --seed 123456  2>&1 | tee train.log".format(i,i,i,i,i))
        os.system(
            "python codet5_main.py --datano {} --output_dir=./saved_models --model_name=model_{}.bin --do_test --test_data_file=../data/fine_tune_data/{}/cve_fixes_test.csv --encoder_block_size 512 --decoder_block_size 256 --eval_batch_size 1 --n_gpu 1".format(i,i,i))

