"""StrataSword attacks — sophisticated single-turn attack techniques"""

from .acrostic_poem import acrostic_poem_encode
from .character_split import character_split_encode
from .contradictory import contradictory_encode
from .opposing import opposing_encode
from .shuffle import shuffle_encode
from .long_text import long_text_encode
from .code_attack import code_attack_encode
from .drattack import drattack_encode
from .script_template import script_template_encode

STRATASWORD_METHODS = {
    "acrostic_poem": acrostic_poem_encode,
    "character_split": character_split_encode,
    "contradictory": contradictory_encode,
    "opposing": opposing_encode,
    "shuffle": shuffle_encode,
    "long_text": long_text_encode,
    "code_attack": code_attack_encode,
    "drattack": drattack_encode,
    "script_template": script_template_encode,
}

__all__ = ["STRATASWORD_METHODS"]