class FastNER:
    """Optional Named Entity Recognition wrapper for human names and physical addresses."""
    
    def __init__(self, model_name: str = "en_core_web_sm"):
        try:
            import spacy
            self.nlp = spacy.load(model_name)
            self.enabled = True
        except ImportError:
            self.enabled = False
            self.nlp = None

    def extract_entities(self, text: str):
        if not self.enabled or not self.nlp:
            return []
        doc = self.nlp(text)
        return [(ent.text, ent.label_) for ent in doc.ents if ent.label_ in ["PERSON", "GPE", "LOC"]]
