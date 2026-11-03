class utilisateur :

    def __init__(self, nom, prenom):
        self.nom = nom
        self.prenom = nom
        self._private_key = None
        self.public_key = None

    def boite_magic(self, magic_number, cle1, cle2):
        