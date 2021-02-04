import React, { useState } from 'react';
import PropTypes from 'prop-types';

async function loginUser(credentials) {
    return fetch('http://localhost:5000/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(credentials)
    })
      .then(data => data.json())
}

export default function Login({ setToken }) {
    const [email, setEmail] = useState();
    const [password, setPassword] = useState();

    const handleSubmit = async e => {
        e.preventDefault();
        const data = await loginUser({
          email,
          password
        });
        setToken(data.access_token);
        console.log(data.access_token)
      }
    

    return (
        <form>
            <h3>Iniciar sesión</h3>

            <div className="form-group">
                <label>Correo</label>
                <input type="email" className="form-control" placeholder="alguno@uniandes.edu.co" onChange={e => setEmail(e.target.value)}/>
            </div>

            <div className="form-group">
                <label>Contraseña</label>
                <input type="password" className="form-control" placeholder="*********" onChange={e => setPassword(e.target.value)} />
            </div>

            <div className="form-group">
                <div className="custom-control custom-checkbox">
                    <input type="checkbox" className="custom-control-input" id="customCheck1" />
                    <label className="custom-control-label" htmlFor="customCheck1">Recuerdame</label>
                </div>
            </div>

            <button type="submit" className="btn btn-dark btn-lg btn-block">Iniciar sesión</button>
            <p className="forgot-password text-right">
                ¿Olvidaste tu <a href="#">contraseña?</a>
            </p>
        </form>
    );
}

Login.propTypes = {
    setToken: PropTypes.func.isRequired
}