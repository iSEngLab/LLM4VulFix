## Training
### Raw

mkdir -p ./24-Jan-2023/
#Source
python run.py \
        --do_train \
        --do_eval \
        --model_type gpt2 \
        --model_name source\
        --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
        --train_filename ../data/fine_tune_data/gptdata/buggy_methods_train_trans.txt,../data/fine_tune_data/gptdata/fixed_methods_train_trans.txt \
        --dev_filename ../data/fine_tune_data/gptdata/buggy_methods_val_trans.txt,../data/fine_tune_data/gptdata/fixed_methods_val_trans.txt \
        --output_dir ./24-Jan-2023/ \
        --max_source_length 512 \
        --max_target_length 512 \
        --beam_size 50 \
        --train_batch_size 16 \
        --eval_batch_size 16 \
        --learning_rate 5e-5 \
        --patience 2\
        --num_train_epochs 50 \
        2>&1 | tee ./24-Jan-2023/train.log

# Source Testing

python run.py \
         --do_test \
         --model_type gpt2 \
         --model_name source\
         --load_model_path ./24-Jan-2023/checkpoint-best-ppl/source.bin \
         --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
         --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_test_ori.txt \
         --output_dir ./24-Jan-2023/ \
         --max_source_length 512 \
         --max_target_length 512 \
         --beam_size 50 \
         --train_batch_size 8 \
         --eval_batch_size 8 \
         --learning_rate 5e-5 \
         --num_train_epochs 30 \
         2>&1 | tee ./24-Jan-2023/eval-23-Aug.log

#Target
python run.py \
        --do_train \
        --do_eval \
        --model_type gpt2 \
        --load_model_path ./24-Jan-2023/checkpoint-best-ppl/source.bin \
        --model_name target\
        --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
        --train_filename ../data/fine_tune_data/gptdata/buggy_methods_train_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_train_ori.txt \
        --dev_filename ../data/fine_tune_data/gptdata/buggy_methods_val_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_val_ori.txt \
        --output_dir ./24-Jan-2023/ \
        --max_source_length 512 \
        --max_target_length 512 \
        --beam_size 50 \
        --train_batch_size 16 \
        --eval_batch_size 16 \
        --learning_rate 5e-5 \
        --patience 2\
        --num_train_epochs 50 \
        2>&1 | tee ./24-Jan-2023/train.log

#Target Testing

python run.py \
         --do_test \
         --model_type gpt2 \
         --model_name target\
         --load_model_path ./24-Jan-2023/checkpoint-best-ppl/target.bin \
         --model_name_or_path microsoft/CodeGPT-small-java-adaptedGPT2 \
         --test_filename ../data/fine_tune_data/gptdata/buggy_methods_test_ori.txt,../data/fine_tune_data/gptdata/fixed_methods_test_ori.txt \
         --output_dir ./24-Jan-2023/ \
         --max_source_length 512 \
         --max_target_length 512 \
         --beam_size 50 \
         --train_batch_size 8 \
         --eval_batch_size 8 \
         --learning_rate 5e-5 \
         --num_train_epochs 30 \
         2>&1 | tee ./24-Jan-2023/eval-23-Aug.log