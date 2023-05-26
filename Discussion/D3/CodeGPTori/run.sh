## Training
### Raw

mkdir -p ./24-Jan-2023/
#
python run.py \
        --do_train \
        --do_eval \
        --model_type gpt2 \
        --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
        --train_filename ../data/fine_tune_data/gptdata/buggy_methods_train_diff.txt,../data/fine_tune_data/gptdata/fixed_methods_train_diff.txt \
        --dev_filename ../data/fine_tune_data/gptdata/buggy_methods_val_diff.txt,../data/fine_tune_data/gptdata/fixed_methods_val_diff.txt \
        --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_diff.txt,../data/fine_tune_data/gptdata/fixed_methods_test_diff.txt \
        --output_dir ./24-Jan-2023/ \
        --max_source_length 512 \
        --max_target_length 512 \
        --beam_size 50 \
        --model_name diff \
        --train_batch_size 8 \
        --eval_batch_size 8 \
        --learning_rate 5e-5 \
        --num_train_epochs 30 \
        2>&1 | tee ./24-Jan-2023/train.log

# ## Testing

python run.py \
         --do_test \
         --model_type gpt2 \
         --load_model_path ./24-Jan-2023/checkpoint-last/diff.bin \
         --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
         --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_diff.txt,../data/fine_tune_data/gptdata/fixed_methods_test_diff.txt \
         --output_dir ./24-Jan-2023/ \
         --max_source_length 512 \
         --max_target_length 512 \
         --beam_size 50 \
         --train_batch_size 8 \
         --eval_batch_size 8 \
         --learning_rate 5e-5 \
         --model_name diff \
         --num_train_epochs 30 \
         2>&1 | tee ./24-Jan-2023/eval-23-Aug.log

python run.py \
        --do_train \
        --do_eval \
        --model_type gpt2 \
        --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
        --train_filename ../data/fine_tune_data/gptdata/buggy_methods_train_prompt.txt,../data/fine_tune_data/gptdata/fixed_methods_train_prompt.txt \
        --dev_filename ../data/fine_tune_data/gptdata/buggy_methods_val_prompt.txt,../data/fine_tune_data/gptdata/fixed_methods_val_prompt.txt \
        --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_prompt.txt,../data/fine_tune_data/gptdata/fixed_methods_test_prompt.txt \
        --output_dir ./24-Jan-2023/ \
        --max_source_length 512 \
        --max_target_length 512 \
        --beam_size 50 \
        --model_name prompt \
        --train_batch_size 8 \
        --eval_batch_size 8 \
        --learning_rate 5e-5 \
        --num_train_epochs 30 \
        2>&1 | tee ./24-Jan-2023/train.log

# ## Testing

python run.py \
         --do_test \
         --model_type gpt2 \
         --load_model_path ./24-Jan-2023/checkpoint-last/prompt.bin \
         --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
         --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_prompt.txt,../data/fine_tune_data/gptdata/fixed_methods_test_prompt.txt \
         --output_dir ./24-Jan-2023/ \
         --max_source_length 512 \
         --max_target_length 512 \
         --beam_size 50 \
         --train_batch_size 8 \
         --eval_batch_size 8 \
         --learning_rate 5e-5 \
         --model_name prompt \
         --num_train_epochs 30 \
         2>&1 | tee ./24-Jan-2023/eval-23-Aug.log