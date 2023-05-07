import os
if __name__ =="__main__":
    os.system("python gpt2_main.py --output_dir=./saved_models --model_name=model.bin --do_train --train_data_file=../data/fine_tune_data/cve_fixes_train_gpt.csv --eval_data_file=../data/fine_tune_data/cve_fixes_val_gpt.csv --test_data_file=../data/fine_tune_data/cve_fixes_test_gpt.csv --epochs 75 --encoder_block_size 768 --decoder_block_size 768 --train_batch_size 8 --eval_batch_size 8 --learning_rate 2e-5 --max_grad_norm 1.0 --n_gpu 2 --evaluate_during_training --seed 123456  2>&1 | tee train.log")
    os.system("python gpt2_main.py --output_dir=./saved_models --model_name=model.bin --do_test --test_data_file=../data/fine_tune_data/cve_fixes_test_gpt.csv --encoder_block_size 768 --decoder_block_size 1024 --eval_batch_size 1 --n_gpu 1")
