from deep_translator import GoogleTranslator


def translate_to_english(text: str, language_code: str):
    if language_code == "en":
        return {
            "translated_text": text,
            "translation_status": "not_required",
        }

    try:
        translated_text = GoogleTranslator(
            source="auto",
            target="en",
        ).translate(text)

        return {
            "translated_text": translated_text,
            "translation_status": "translated",
        }

    except Exception:
        return {
            "translated_text": text,
            "translation_status": "failed",
        }