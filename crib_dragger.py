from colorama import Fore, Style
import os
from xor_text_finder import *

def print_text(text_list: list[bytes]) -> None:
    """
    Print each text from the list with its corresponding index.
    """
    for i, x in enumerate(text_list):
        try:
            decoded = x.decode()
        except Exception:
            decoded = repr(x)
        print(f'Index {i}: {decoded}')
    print('\n')


class CribDragger:
    def __init__(self,word_finder=None):
        self.word_finder = word_finder or WordFinder(True)
    
    def initialize_word_list(self,default=True,word_list=None):
        if default:
            self.word_finder.init_words(True)
        else:
            self.word_finder.init_custom_words(word_list)
    
    def get_input_key(self,target_key: bytes, target_texts: list[bytes]) -> bytes:
        """
        Prompts the user to manually select a target key from XOR-ed texts.
        Returns the newly computed key or falls back to the original target_key.
        """
        # Only use texts longer than the current key
        set_text = [x for x in target_texts if len(x) > len(target_key)]
        xored_text = xor_key_text_list(target_key, set_text)
        print(Fore.YELLOW + "\tPlease provide your target key:" + Style.RESET_ALL)
        print_text(xored_text)
        try:
            potential_key_id = int(
                input(Fore.LIGHTYELLOW_EX + "\n\tEnter the index of the target key: " + Style.RESET_ALL)
            )
            new_text = input(Fore.GREEN + "\tEnter the corresponding plaintext: " + Style.RESET_ALL)
            new_text_bytes = new_text.encode()
            assert check_ascii(new_text_bytes), "Input contains non-ASCII characters."
            new_key = xor_key_text(new_text_bytes, set_text[potential_key_id])
            if check_potential_stream(new_key, set_text, strict=False):
                return new_key
            return target_key
        except KeyboardInterrupt:
            print(Fore.RED + "\nUser interrupted. Returning current target key." + Style.RESET_ALL)
            return target_key
        except Exception as e:
            print(Fore.RED + f"\nError: {e}. Returning current target key." + Style.RESET_ALL)
            return target_key


    def check_new_target_keys(self,new_target_keys: list[bytes], set_text: list[bytes]) -> list[bytes] | bytes:
        """
        Given a list of candidate keys, display their XOR-decoded outputs and ask the user
        if any of them are correct. Returns the chosen key or a new candidate list.
        """
        # Filter candidate keys to include those with the maximum length.
        max_length = len(max(new_target_keys, key=len))
        small_keys = [x for x in new_target_keys if len(x) == max_length]
        for i, small_key in enumerate(small_keys):
            print(Fore.CYAN + f"\tTesting Candidate Key {i}:" + Style.RESET_ALL)
            # Decode each candidate's output.
            decoded_results = xor_key_text_list(small_key, set_text)
            try:
                print("\n".join([result.decode() for result in decoded_results]))
            except Exception:
                print(decoded_results)
            print("\n")
        try:
            result = input(Fore.LIGHTCYAN_EX + "\tDo any of the above keys look correct? (yes/no): " + Style.RESET_ALL)
            if result and result[0].lower() in ['1', 'y']:
                result_idx = int(
                    input(Fore.GREEN + "\tEnter the index of the correct key: " + Style.RESET_ALL)
                )
                return small_keys[result_idx]
            else:
                # Return remaining candidates for further testing.
                return [x for x in new_target_keys if x not in small_keys]
        except KeyboardInterrupt:
            print(Fore.RED + "\nUser interrupted. Returning the first candidate key." + Style.RESET_ALL)
            return small_keys[0] if small_keys else new_target_keys[0]


    def get_new_keys(self,new_target_keys: list[bytes] | bytes, set_text: list[bytes]) -> bytes | None:
        """
        Iteratively ask the user to choose among candidate keys until a single key is determined.
        """
        new_keys = new_target_keys
        while isinstance(new_keys, list):
            # If a single key is directly returned, then use it.
            if isinstance(new_keys, bytes):
                return new_keys
            new_keys = self.check_new_target_keys(new_keys, set_text)
            if not new_keys:
                return None
        return new_keys


    def get_invalid_idxs(self,xored_outputs):
        invalid_idxs = []
        for i, out in enumerate(xored_outputs):
            if not check_ascii(out) or not extra_strict_check(out):
                invalid_idxs.append(i)
        return invalid_idxs

    def check_and_remove_invalid_chars(self,target_key,set_text):
        xored_outputs = xor_key_text_list(target_key,set_text)
        invalid_ids = self.get_invalid_idxs(xored_outputs)
        invalid_pts = []
        if invalid_ids:
            print(Fore.YELLOW + "\n\tWarning: Some outputs contain invalid characters:" + Style.RESET_ALL)
            for i in invalid_ids:
                print(Fore.RED + f"[idx {i}] = {xored_outputs[i].decode(errors='ignore')}" + Style.RESET_ALL)
            choice = input(Fore.LIGHTYELLOW_EX + "\nRemove these and continue? (y/n): " + Style.RESET_ALL)
            if choice[:1].lower() in ['1','y']:
                invalid_pts.extend([set_text[i] for i in invalid_ids])
                set_text = [x for i, x in enumerate(set_text) if i not in invalid_ids]
                print(Fore.GREEN + f"\tRemoved {len(invalid_ids)} invalid messages. Retrying..." + Style.RESET_ALL)
                return set_text,invalid_pts
            else:
                print(Fore.RED + "\tReturning current key." + Style.RESET_ALL)
                return set_text,invalid_pts
        return set_text,invalid_pts


    def validate_key(self,target_key,set_text):
        print(Fore.MAGENTA + "\tTesting New Key:" + Style.RESET_ALL)
        xored_outputs = xor_key_text_list(target_key,set_text)
        print_text(xored_outputs)
        print("\n")
        result = input(Fore.LIGHTMAGENTA_EX + "Does this key seem correct? (yes/no): " + Style.RESET_ALL)
        if isinstance(result,str):
            if result[:1].lower() in ['1','y']:
                return target_key
            else:
                return None


    def interactive_crib_dragging(self,target_key,set_text):
        my_new_key = target_key
        self.invalid_pts = []
        while len(set_text)!=1:
            target_key = my_new_key
            set_text =  [x for x in set_text if len(x)>len(target_key)]
            if len(set_text)==1:
                return target_key
            try:
                new_target_key = self.word_finder.identify_potential_keys(target_key,set_text,2,True)
                if isinstance(new_target_key,list):
                    if new_target_key:
                        temp_key = sorted(new_target_key,key=len)[-1]
                        if self.validate_key(temp_key,set_text):
                            new_target_key = temp_key
                        else:
                            print(Fore.RED + "\tNo valid key extensions found. Returning last known key." + Style.RESET_ALL)
                            return target_key, self.invalid_pts
                    else:
                        print(Fore.RED + "\tNo valid key extensions found. Returning last known key." + Style.RESET_ALL)
                        return target_key, self.invalid_pts
                my_new_key = None
                result = self.validate_key(new_target_key,set_text)
                if result:
                    if target_key != new_target_key:
                        my_new_key = new_target_key
                        continue
                    else:
                        print(Fore.RED + "\tThe key remains unchanged; please provide a new candidate." + Style.RESET_ALL)
                        try:
                            new_target_keys = self.word_finder.identify_potential_keys(new_target_key, set_text, strict_filter=0,add_space=True)
                            my_new_key_ = self.get_new_keys(new_target_keys, set_text)
                            my_new_key = self.validate_key(my_new_key_,set_text)
                            if my_new_key:
                                set_text,invalid_pts_ = self.check_and_remove_invalid_chars(my_new_key,set_text)
                                self.invalid_pts.extend(invalid_pts_)
                        except Exception as e:
                            print(Fore.RED + f"\nError: {e}. Falling back to manual input." + Style.RESET_ALL)
                            my_new_key_ = self.get_input_key(target_key, set_text)
                            my_new_key = self.validate_key(my_new_key_,set_text)
                            if my_new_key:
                                set_text,invalid_pts_ = self.check_and_remove_invalid_chars(my_new_key,set_text)
                                self.invalid_pts.extend(invalid_pts_)
                    if not my_new_key:
                        my_new_key_ = self.get_input_key(target_key, set_text)
                        my_new_key = self.validate_key(my_new_key_,set_text)
                        if my_new_key:
                            set_text,invalid_pts_ = self.check_and_remove_invalid_chars(my_new_key,set_text)
                            self.invalid_pts.extend(invalid_pts_)
                else:
                    my_new_key_ = self.get_input_key(target_key, set_text)
                    my_new_key = self.validate_key(my_new_key_,set_text)
                    if my_new_key:
                        set_text,invalid_pts_ = self.check_and_remove_invalid_chars(my_new_key,set_text)
                        self.invalid_pts.extend(invalid_pts_)
                if not my_new_key:
                    print(Fore.RED + "\nOopsy Daisy, we still haven't found a key." + Style.RESET_ALL)
                    return ((target_key,my_new_key_),self.invalid_pts)
            except KeyboardInterrupt:
                print(Fore.RED + "\nUser interrupted. Returning the current XOR key." + Style.RESET_ALL)
                return ((target_key,my_new_key),self.invalid_pts)
        return ((target_key,my_new_key),self.invalid_pts)
