import os
if __name__ == '__main__':
    os.system("python run.py \
         --do_test \
         --model_type gpt2 \
         --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
         --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_test_ori.txt \
         --output_dir ./24-Jan-2023/ \
         --max_source_length 512 \
         --max_target_length 512 \
         --beam_size 5 \
         --train_batch_size 8 \
         --eval_batch_size 8 \
         --learning_rate 5e-5 \
         --num_train_epochs 30 \
         --fine_tune_factor 0\
         2>&1 | tee ./24-Jan-2023/eval-23-Aug.log")
    splits = [0.2,0.4,0.6,0.8]
    for i in splits:
        os.system("python run.py \
        --do_train \
        --do_eval \
        --model_type gpt2 \
        --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
        --train_filename ../data/fine_tune_data/gptdata/buggy_methods_train_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_train_ori.txt \
        --dev_filename ../data/fine_tune_data/gptdata/buggy_methods_val_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_val_ori.txt \
        --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_test_ori.txt \
        --output_dir ./24-Jan-2023/ \
        --max_source_length 512 \
        --max_target_length 512 \
        --beam_size 5 \
        --train_batch_size 8 \
        --eval_batch_size 8 \
        --learning_rate 5e-5 \
        --num_train_epochs 30 \
        --fine_tune_factor {}\
        2>&1 | tee ./24-Jan-2023/train.log".format(i))
        os.system("python run.py \
         --do_test \
         --model_type gpt2 \
         --load_model_path ./24-Jan-2023/checkpoint-best-ppl/{}.bin \
         --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
         --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_test_ori.txt \
         --output_dir ./24-Jan-2023/ \
         --max_source_length 512 \
         --max_target_length 512 \
         --beam_size 5 \
         --train_batch_size 8 \
         --eval_batch_size 8 \
         --learning_rate 5e-5 \
         --num_train_epochs 30 \
         --fine_tune_factor {}\
         2>&1 | tee ./24-Jan-2023/eval-23-Aug.log".format(i,i))