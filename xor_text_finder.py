import os
import string
from collections import Counter
from typing import List, Union, Optional, Tuple, Iterable

import nltk
import inflect
from pwn import xor

# Ensure required NLTK corpora are available.
try:
    from nltk.corpus import brown, words as nltk_words
except ImportError:
    nltk.download('brown')
    nltk.download('words')
    from nltk.corpus import brown, words as nltk_words


def xor_key_text(key: Union[bytes, str], text: Union[bytes, str]) -> bytes:
    """
    XOR the given key with text and return the result.
    The result is truncated to the length of the shorter input.
    """
    if isinstance(key, str):
        key = key.encode()
    if isinstance(text, str):
        text = text.encode()
    target_length = min(len(key), len(text))
    return xor(key, text)[:target_length]


def xor_key_text_list(key: Union[bytes, str],
                      text_list: List[Union[bytes, str]]) -> List[bytes]:
    """
    XOR the given key with each text in the provided list.
    """
    return [xor_key_text(key, text) for text in text_list]


def extra_strict_check(sentence: Union[bytes, str]) -> bool:
    """
    Checks that the sentence does not contain any disallowed punctuation characters.
    Disallowed characters include: " # $ % & \ ( ) * + / < = > @ [ \ ] ^ ` | ~
    """
    if isinstance(sentence, bytes):
        sentence = sentence.decode(errors='ignore')
    forbidden_chars = '"#$%&\\()*+/<=>@[\\]^`|~'
    return not any(c in forbidden_chars for c in sentence)


def check_ascii(text: Union[bytes, str]) -> bool:
    """
    Check if the text is composed entirely of printable ASCII characters.
    """
    if isinstance(text, bytes):
        try:
            text = text.decode()
        except UnicodeDecodeError:
            return False
    return all(c in string.printable for c in text)


def check_potential_stream(target_key: Union[bytes, str],
                           text_list: List[Union[bytes, str]],
                           strict: bool = False) -> Optional[List[bytes]]:
    """
    XOR each text in text_list with target_key and verify that all results are ASCII.
    If 'strict' is True, each result must also pass the extra_strict_check.
    """
    xored_stream = xor_key_text_list(target_key, text_list)
    if all(check_ascii(c) for c in xored_stream):
        if strict:
            if all(extra_strict_check(c) for c in xored_stream):
                return xored_stream
            return None
        return xored_stream
    return None


def verify_substring_keys(keys: List[str]) -> bool:
    """
    Returns True if the smallest key (by length) is a substring of every key in the list.
    """
    if not keys:
        return False
    smallest_key = min(keys, key=len)
    return all(smallest_key in key for key in keys)


class WordFinder:
    """
    A utility class for finding and validating words and potential keys based on
    word frequency, known plaintext, and XOR decoding.
    """
    def __init__(self, capitalize: bool = False) -> None:
        # Pre-load all word variations and the word set.
        #self.all_words: List[str] = self.get_all_words(capitalize)
        #self.all_words_set = set(self.all_words)
        #self.freq_dist = self._get_frequency_dict()
        pass

    def init_words(self,capitalize):
        self.all_words: List[str] = self.get_all_words(capitalize)
        self.all_words_set = set(self.all_words)
        self.freq_dist = self._get_frequency_dict()


    def get_words(self) -> List[str]:
        """
        Retrieve a list of singular words from the NLTK corpus.
        """
        return nltk_words.words()

    def get_plural_words(self, singular_words: List[str]) -> List[str]:
        """
        Generate plural forms for a list of singular words.
        """
        p = inflect.engine()
        return [p.plural(word) for word in singular_words]

    def get_capital_words(self, words_list: List[str]) -> List[str]:
        """
        Return the capitalized version of each word in the list.
        """
        return [word.capitalize() for word in words_list]

    def get_all_words(self, capitalize: bool = False) -> List[str]:
        """
        Combine singular and plural words (and optionally their capitalized forms)
        into a sorted list (sorted by word length).
        """
        singular_words = self.get_words()
        plural_words = self.get_plural_words(singular_words)
        combined = singular_words + plural_words
        if capitalize:
            combined += self.get_capital_words(combined)
        return sorted(set(combined), key=len)

    def _get_frequency_dict(self) -> nltk.FreqDist:
        """
        Compute and return the frequency distribution of words from the Brown corpus.
        """
        brown_words = brown.words()
        return nltk.FreqDist(brown_words)

    def sort_with_frequencies(self, matching_words: List[str]) -> List[str]:
        """
        Sort matching words based on their frequency in the Brown corpus
        (highest frequency first). Words with no recorded frequency are omitted.
        """
        scored_words = []
        for word in matching_words:
            freq = 0
            if word in self.freq_dist:
                freq = self.freq_dist[word]
                if word.lower() in self.freq_dist:
                    freq = max(freq, self.freq_dist[word.lower()])
            elif word.lower() in self.freq_dist:
                freq = self.freq_dist[word.lower()]
            if freq:
                scored_words.append((word, freq))
        sorted_words = sorted(scored_words, key=lambda x: x[1], reverse=True)
        return [word for word, _ in sorted_words]

    def get_matching_words(self,
                           prefix: str,
                           words_list: List[str],
                           add_space: bool = False) -> List[str]:
        """
        Retrieve words from the loaded dictionary that start with the given prefix.
        Returns a list of candidate sentences formed by replacing the last word.
        """
        matching_words = [word for word in self.all_words if word.startswith(prefix)]
        sorted_words = self.sort_with_frequencies(matching_words)
        base_sentence = ' '.join(words_list[:-1])
        potential_sentences = [f"{base_sentence} {word}" for word in sorted_words]
        if add_space:
            potential_sentences = [sentence + ' ' for sentence in potential_sentences]
        return potential_sentences

    def get_matching_words_with_known_index_and_plaintext(self,
                                                          target: str,
                                                          indices: Iterable[int]) -> List[str]:
        """
        Retrieve words that match the target pattern at the specified indices.
        """
        return [
            word for word in self.all_words
            if len(word) == len(target) and all(word[idx] == target[idx] for idx in indices)
        ]

    def match_sentence(self,
                       sentence: Union[bytes, str],
                       strict: bool = False,
                       add_space: bool = False) -> Optional[List[str]]:
        """
        Analyze a sentence and, if the last word is incomplete or unrecognized,
        return a list of candidate sentences with matching completions.
        """
        if isinstance(sentence, bytes):
            sentence = sentence.decode(errors='ignore')
        words = sentence.split()
        if not words:
            return None

        last_word = words[-1]
        # Only consider matching if the last word has no punctuation.
        if last_word and not any(c in string.punctuation for c in last_word):
            if strict:
                if last_word not in self.all_words_set:
                    return self.get_matching_words(last_word, words, add_space)
            else:
                if len(last_word) >= 2:
                    return self.get_matching_words(last_word, words, add_space)
        return None

    def check_sentence(self,
                       sentence: Union[bytes, str],
                       strict: bool = True) -> bool:
        """
        Check if a sentence is valid (printable ASCII) and, if strict, that every word is recognized.
        """
        if isinstance(sentence, bytes):
            try:
                sentence = sentence.decode()
            except UnicodeDecodeError:
                return False
        if check_ascii(sentence):
            cleaned_sentence = sentence.translate(str.maketrans('', '', string.punctuation))
            words = cleaned_sentence.split()
            if strict:
                return set(words).issubset(self.all_words_set)
            return True
        return False

    def filter_streams(self,
                       key_list: List[Union[bytes, str]],
                       text_list: List[Union[bytes, str]],
                       strict: int) -> Tuple[List[bytes], List[Union[bytes, str]]]:
        """
        For each key in key_list and text in text_list, decode using XOR.
        Returns a tuple of (decoded_texts, corresponding_keys) for those that
        yield valid sentences. If strict == 2, an extra check is applied.
        """
        valid_keys = []
        valid_results = []
        for key in key_list:
            for text in text_list:
                decoded_text = xor_key_text(key, text)
                if self.check_sentence(decoded_text, strict=True):
                    if strict == 2:
                        if extra_strict_check(decoded_text):
                            valid_keys.append(key)
                            valid_results.append(decoded_text)
                    else:
                        valid_keys.append(key)
                        valid_results.append(decoded_text)
        return valid_results, valid_keys

    def identify_potential_keys(self,
                                target_key: Union[bytes, str],
                                target_texts: List[Union[bytes, str]],
                                strict_filter: int,
                                add_space: bool = False) -> Union[str, List[Union[bytes, str]]]:
        """
        Identify potential keys from target_texts based on word frequency and known plaintext hints.
        This function:
          1. Filters texts longer than target_key.
          2. Applies XOR and checks the decoded streams.
          3. Attempts to match incomplete sentences.
          4. Filters and ranks candidate keys.
        Returns either the longest valid key (if candidates share a substring) or a list of keys.
        """
        # Filter texts that are longer than the target key.
        filtered_texts = [text for text in target_texts if len(text) > len(target_key)]
        potential_stream = check_potential_stream(target_key, filtered_texts,strict=strict_filter)
        if potential_stream is None:
            return []

        counted_keys = Counter()
        for i, stream in enumerate(potential_stream):
            matched_sentences = self.match_sentence(stream, strict=False, add_space=add_space)
            if matched_sentences:
                keystreams = xor_key_text_list(filtered_texts[i], matched_sentences)
                results, new_keys = self.filter_streams(keystreams, filtered_texts, strict_filter)
                counted_keys.update(new_keys)

        # Optionally remove the original target_key if not desired.
        counted_keys[target_key] = 0
        if strict_filter == 0 and target_key in counted_keys:
            del counted_keys[target_key]

        new_target_keys = []
        for key in counted_keys:
            if check_potential_stream(key, filtered_texts, strict=strict_filter):
                new_target_keys.append(key)

        # Convert keys to strings if needed for substring verification.
        if verify_substring_keys(new_target_keys):
            # Return the longest key.
            return sorted(new_target_keys, key=lambda k: len(k), reverse=True)[0]
        return new_target_keys
