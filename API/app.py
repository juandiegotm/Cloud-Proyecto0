import enum
from datetime import datetime
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_enum import EnumField
from flask_restful import Api, Resource
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    jwt_refresh_token_required,
    get_jwt_identity,
    get_raw_jwt
)

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'ThisIsHardestThing'
app.config['JWT_SECRET_KEY'] = '!9m@S-dThyIlW[pHQbN^'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

db = SQLAlchemy(app)
ma =Marshmallow(app)
api = Api(app)
jwt = JWTManager(app)

class Usuario(db.Model):
    #__tablename__ = 'usertable'
    id = db.Column( db.Integer, primary_key = True)
    name = db.Column(db.String(30))
    email = db.Column( db.String(50), unique = True )
    password = db.Column (db.String(256))
    eventos = db.relationship('Evento', backref='usuario', lazy=True)

class Usuario_Schema(ma.Schema):
    class Meta:
        fields = ("id", "name", "email", "password", "eventos")

class Categoria(enum.Enum):
    conferencia = "conferencia"
    curso = "curso"
    seminario = "seminario"
    congreso = "congreso"

class TipoAsistencia(enum.Enum):
    virtual = "vitural"
    presencial = "presencial"

class Evento(db.Model):
    id = db.Column( db.Integer, primary_key = True)
    nombre = db.Column(db.String(30), nullable = False)
    categoria = db.Column(db.Enum(Categoria), nullable = False)
    lugar = db.Column( db.String(50) )
    fechaInicio = db.Column(db.DateTime() )
    fechaFinal = db.Column(db.DateTime())
    asistencia = db.Column(db.Enum(TipoAsistencia))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable = False)

class Evento_Schema(ma.Schema):
    categoria = EnumField(Categoria, by_value = True)
    asistencia = EnumField(TipoAsistencia, by_value = True)
    class Meta: 
        fields = ("id", "nombre", "categoria", "lugar", "fechaInicio", "fechaFinal", "asistencia", "usuario_id")


usuario_schema = Usuario_Schema()
usuarios_schema = Usuario_Schema(many = True)

evento_schema = Evento_Schema()
eventos_schema = Evento_Schema(many = True)

class RecursoRegistro(Resource):
    def post(self):
        usuario = Usuario.query.filter_by(email = request.json["email"]).first()

        if usuario: 
            return 'Ya existe un usuario con el correo dado', 200

        try:
            password_encrypted = generate_password_hash(request.json["password"], method='sha256')
            nuevo_usuario = Usuario(name = request.json["name"], email = request.json["email"], password = password_encrypted)

            db.session.add(nuevo_usuario)
            db.session.commit()

            data = usuario_schema.dump(nuevo_usuario)
            access_token = create_access_token(identity=data)
        
            return {
                'message': f'User {request.json["email"]} was created',
                'access_token': access_token,
                'data': data
            }

        except Exception as e:
            print(e)
            return {'message': 'Something went wrong'}, 500

class RecursoAutenticacion(Resource):
    def post(self):
        usuario = Usuario.query.filter_by(email = request.json["email"]).first()
        if usuario and check_password_hash(usuario.password, request.json["password"]):
            return { "success": True, "msg": "Login exitoso"}
        else:
            return { "error": True, "msg": "La combinación usuario/contraseña no está dentro de nuestros registros"}

class RecursoListarEventos(Resource):
    def get(self):
        eventos = Evento.query.all()
        return eventos_schema.dump(eventos)

    def post(self):
        nuevo_evento=Evento(
            nombre = request.json['nombre'], 
            categoria = request.json['categoria'],
            lugar = request.json['lugar'],
            fechaInicio = datetime.fromtimestamp(request.json['fechaInicio']),
            fechaFinal = datetime.fromtimestamp(request.json['fechaFinal']),
            asistencia = request.json['asistencia'],
            usuario_id = request.json['usuario_id'])
        db.session.add(nuevo_evento)
        db.session.commit()
        return evento_schema.dump(nuevo_evento)

class RecursoUnEvento(Resource):
    def get(self, id_Evento):
        evento = Evento.query.get_or_404(id_Evento)
        return evento_schema.dump(evento)
    
    def put(self, id_Evento):
        evento = Evento.query.get_or_404(id_Evento)
        fields_allow_changes = ['nombre', 'categoria', 'lugar', 'fechaInicio', 'fechaFinal', 'asistencia', 'usuario_id']
        
        for field in request.json:
            if field in fields_allow_changes:
                if field == 'fechaInicio' or field == 'fechaFinal':
                    setattr(evento, field, datetime.fromtimestamp(request.json[field]))
                else:
                    setattr(evento, field, request.json[field])   

        
        db.session.commit()
        return evento_schema.dump(evento)

    def delete(self, id_Evento):
        evento = Evento.query.get_or_404(id_Evento)
        db.session.delete(evento)
        db.session.commit()
        return '', 204

class RecursoEventoDeUsuario(Resource):
    def get(self, id_usuario):
        eventos = Evento.query.filter_by(usuario_id = id_usuario)
        eventos_json = eventos_schema.dump(eventos)
        if not eventos_json:
            return '',404
        return eventos_json
        
api.add_resource(RecursoListarEventos, '/eventos')
api.add_resource(RecursoUnEvento, '/eventos/<int:id_Evento>')
api.add_resource(RecursoRegistro, '/registro')
api.add_resource(RecursoAutenticacion, '/login')
api.add_resource(RecursoEventoDeUsuario, '/usuarios/<int:id_usuario>/eventos')

if __name__ == '__main__':
    app.run(debug=True)