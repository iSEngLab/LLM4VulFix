from transformers import AutoTokenizer
#codegen tokenizer长度50295
#codegpt 50257
from tokenizers import Tokenizer
from tokenizers.models import WordLevel
from tokenizers.pre_tokenizers import Whitespace
from tokenizers.trainers import WordLevelTrainer

tokenizer = Tokenizer(WordLevel(unk_token="[UNK]"))
tokenizer.pre_tokenizer = Whitespace()

trainer = WordLevelTrainer(vocab_size=50257,min_frequency=2)

tokenizer.train(files=['./gptdata/buggy_methods_test_ori.txt','./gptdata/fixed_methods_test_ori.txt',
                       './gptdata/buggy_methods_val_ori.txt','./gptdata/fixed_methods_val_ori.txt',
                       './gptdata/buggy_methods_train_ori.txt','./gptdata/fixed_methods_train_ori.txt'], trainer=trainer)

# Save the files
tokenizer.save("codegpt.json")

print('done')