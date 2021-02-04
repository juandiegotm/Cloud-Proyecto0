import React, { useState, useEffect } from "react";
import { Redirect } from 'react-router-dom';

const EventosList = ({ token }) => {

  const [pokemons, setPokemons] = useState()

  // useEffect(() => {
  //   setPokemons(pokemonsData);
  // }, [pokemonsData]);

  return (
    <table className="table">
      <thead className="thead-dark">
        <tr>
          <th scope="col">#</th>
          <th scope="col">
            {" "}

          </th>
          <th scope="col">
            {" "}
          </th>
          <th scope="col">
            {" "}
          </th>
          <th scope="col">
            {" "}
          </th>
          <th scope="col">
            {" "}
          </th>
          <th scope="col">
          </th>
        </tr>
      </thead>
      <tbody style={{ "textAlign": "left" }}>
        {pokemons.map((pokemon, index) =>
          returnPokemonItem(pokemon, index + 1)
        )}
      </tbody>
    </table>
  );
};

const returnPokemonItem = (pokemon, index) => {
  return (
    <tr>
      <th scope="row">{index}</th>
      <td>
        <img
          src={pokemon.ThumbnailImage}
          alt={`Imagen de ${pokemon.name}`}
        ></img>
      </td>
      <td>{pokemon.name}</td>
      <td>{pokemon.description}</td>
      <td>{pokemon.height}</td>
      <td> Hola </td>
    </tr>
  );
};

export default EventosList;
