import os
if __name__ =="__main__":
    i = int(input())
    if i==0:
        os.system(
            "python codebert_main.py --output_dir=./saved_models --model_name=diff.bin --do_train --train_data_file=../data/fine_tune_data/cve_fixes_train_diff.csv --eval_data_file=../data/fine_tune_data/cve_fixes_val_diff.csv --test_data_file=../data/fine_tune_data/cve_fixes_test_diff.csv --epochs 75 --encoder_block_size 512 --decoder_block_size 256 --train_batch_size 8 --eval_batch_size 8 --learning_rate 2e-5 --max_grad_norm 1.0 --n_gpu 1 --evaluate_during_training --seed 123456  2>&1 | tee train.log")
        os.system(
            "python codebert_main.py --res_name diff --output_dir=./saved_models --model_name=diff.bin --do_test --test_data_file=../data/fine_tune_data/cve_fixes_test_diff.csv --encoder_block_size 512 --decoder_block_size 256 --eval_batch_size 1 --n_gpu 1")
    if i==1:
        os.system(
            "python codebert_main.py --output_dir=./saved_models --model_name=prompt.bin --do_train --train_data_file=../data/fine_tune_data/cve_fixes_train_prompt.csv --eval_data_file=../data/fine_tune_data/cve_fixes_val_prompt.csv --test_data_file=../data/fine_tune_data/cve_fixes_test_prompt.csv --epochs 75 --encoder_block_size 512 --decoder_block_size 256 --train_batch_size 8 --eval_batch_size 8 --learning_rate 2e-5 --max_grad_norm 1.0 --n_gpu 1 --evaluate_during_training --seed 123456  2>&1 | tee train.log")
        os.system(
            "python codebert_main.py --res_name prompt --output_dir=./saved_models --model_name=prompt.bin --do_test --test_data_file=../data/fine_tune_data/cve_fixes_test_prompt.csv --encoder_block_size 512 --decoder_block_size 256 --eval_batch_size 1 --n_gpu 1")
    if i==2:
        os.system(
            "python codebert_main.py --output_dir=./saved_models --model_name=diff.bin --do_train --train_data_file=../data/fine_tune_data/cve_fixes_train_diff.csv --eval_data_file=../data/fine_tune_data/cve_fixes_val_diff.csv --test_data_file=../data/fine_tune_data/cve_fixes_test_diff.csv --epochs 75 --encoder_block_size 512 --decoder_block_size 256 --train_batch_size 8 --eval_batch_size 8 --learning_rate 2e-5 --max_grad_norm 1.0 --n_gpu 1 --evaluate_during_training --seed 123456  2>&1 | tee train.log")
        os.system(
            "python codebert_main.py --res_name diff --output_dir=./saved_models --model_name=diff.bin --do_test --test_data_file=../data/fine_tune_data/cve_fixes_test_diff.csv --encoder_block_size 512 --decoder_block_size 256 --eval_batch_size 1 --n_gpu 1")
        os.system(
            "python codebert_main.py --output_dir=./saved_models --model_name=prompt.bin --do_train --train_data_file=../data/fine_tune_data/cve_fixes_train_prompt.csv --eval_data_file=../data/fine_tune_data/cve_fixes_val_prompt.csv --test_data_file=../data/fine_tune_data/cve_fixes_test_prompt.csv --epochs 75 --encoder_block_size 512 --decoder_block_size 256 --train_batch_size 8 --eval_batch_size 8 --learning_rate 2e-5 --max_grad_norm 1.0 --n_gpu 1 --evaluate_during_training --seed 123456  2>&1 | tee train.log")
        os.system(
            "python codebert_main.py --res_name prompt --output_dir=./saved_models --model_name=prompt.bin --do_test --test_data_file=../data/fine_tune_data/cve_fixes_test_prompt.csv --encoder_block_size 512 --decoder_block_size 256 --eval_batch_size 1 --n_gpu 1")

