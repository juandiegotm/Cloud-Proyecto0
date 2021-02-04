import React, { Component } from "react";

export default class SignUp extends Component {
    render() {
        return (
            <form>
                <h3>Register</h3>

                <div className="form-group">
                    <label>Nombre</label>
                    <input type="text" className="form-control" placeholder="Juanito Pérez" />
                </div>


                <div className="form-group">
                    <label>Correo</label>
                    <input type="email" className="form-control" placeholder="alguien@uniandes.edu.co" />
                </div>

                <div className="form-group">
                    <label>Contraseña</label>
                    <input type="password" className="form-control" placeholder="************" />
                </div>

                <button type="submit" className="btn btn-dark btn-lg btn-block">Enviar</button>
                <p className="forgot-password text-right">
                    ¿Ya estás <a href="#">registrado?</a>
                </p>
            </form>
        );
    }
}