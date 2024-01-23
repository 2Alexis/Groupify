package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const usersFile = "login.json"

var Token string
var expirationTime time.Time

type Album struct {
	Nom        string `json:"name"`
	ImageURL   string `json:"images"`
	DateSortie string `json:"release_date"`
	TotalSons  int    `json:"total_tracks"`
}
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Add other user-related fields as needed
}

var users []User

type Son struct {
	Nom           string `json:"name"`
	AlbumCoverURL string `json:"album_cover_url"`
	NomAlbum      string `json:"album_name"`
	NomArtiste    string `json:"artist_name"`
	DateSortie    string `json:"release_date"`
	LienSpotify   string `json:"spotify_link"`
}

func main() {

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/album/jul", albumHandler)
	http.HandleFunc("/track/sdm", trackHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Serveur en cours d'écoute sur le port :8080")
	http.ListenAndServe(":8080", nil)
}

func albumHandler(w http.ResponseWriter, r *http.Request) {

	Token, _, err := getAccessToken()
	if err != nil {
		http.Error(w, "Erreur lors de l'obtention du token d'accès: "+err.Error(), http.StatusInternalServerError)
		return
	}

	albums, err := getArtistAlbums("3IW7ScrzXmPvZhB27hmfgy", Token)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des données depuis l'API de Spotify: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/album.html")
	if err != nil {
		http.Error(w, "Erreur lors de la création du modèle HTML: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, albums)
	if err != nil {
		http.Error(w, "Erreur lors de l'affichage de la page: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func trackHandler(w http.ResponseWriter, r *http.Request) {
	Token, _, err := getAccessToken()
	if err != nil {
		http.Error(w, "Erreur lors de l'obtention du token d'accès: "+err.Error(), http.StatusInternalServerError)
		return
	}

	son, err := getTrackInfo("0EzNyXyU7gHzj2TN8qYThj", Token)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des données depuis l'API de Spotify: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/track.html")
	if err != nil {
		http.Error(w, "Erreur lors de la création du modèle HTML: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, son)
	if err != nil {
		http.Error(w, "Erreur lors de l'affichage de la page: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func getArtistAlbums(artistID, Token string) ([]Album, error) {

	apiURL := fmt.Sprintf("https://api.spotify.com/v1/artists/%s/albums", artistID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+Token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("statut de la réponse non ok: %d", resp.StatusCode)
	}

	var response struct {
		Items []struct {
			Nom    string `json:"name"`
			Images []struct {
				URL string `json:"url"`
			} `json:"images"`
			DateSortie string `json:"release_date"`
			TotalSons  int    `json:"total_tracks"`
		} `json:"items"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	var albums []Album
	for _, item := range response.Items {
		album := Album{
			Nom:        item.Nom,
			ImageURL:   item.Images[0].URL,
			DateSortie: item.DateSortie,
			TotalSons:  item.TotalSons,
		}
		albums = append(albums, album)
	}

	return albums, nil
}

func getTrackInfo(trackID, Token string) (Son, error) {
	apiURL := fmt.Sprintf("https://api.spotify.com/v1/tracks/%s", trackID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return Son{}, err
	}

	req.Header.Set("Authorization", "Bearer "+Token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Son{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Son{}, fmt.Errorf("statut de la réponse non ok: %d", resp.StatusCode)
	}

	var response struct {
		Nom   string `json:"name"`
		Album struct {
			Nom    string `json:"name"`
			Images []struct {
				URL string `json:"url"`
			} `json:"images"`
		} `json:"album"`
		Artistes []struct {
			Nom string `json:"name"`
		} `json:"artists"`
		DateSortie   string
		ExternalURLs map[string]string `json:"external_urls"`
	}

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return Son{}, err
	}

	son := Son{
		Nom:           response.Nom,
		AlbumCoverURL: response.Album.Images[0].URL,
		NomAlbum:      response.Album.Nom,
		NomArtiste:    response.Artistes[0].Nom,
		DateSortie:    "2022-12-02",
		LienSpotify:   response.ExternalURLs["spotify"],
	}

	return son, nil
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Erreur lors de la création du modèle HTML: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Erreur lors de l'affichage de la page d'accueil: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func getAccessToken() (string, time.Time, error) {

	clientID := "8a6ceee68c3b4ab08b04e844f0b7e541"
	clientSecret := "b6b6e386085e4ed78b52234b2a21d01d"

	//requête pour obtenir le token
	tokenURL := "https://accounts.spotify.com/api/token"
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	// Vérifiez le code de statut de la réponse
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("statut de la réponse non ok: %d", resp.StatusCode)
	}

	// Décodez le corps de la réponse JSON pour obtenir le token
	var response struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", time.Time{}, err
	}

	expirationTime := time.Now().Add(time.Second * time.Duration(response.ExpiresIn))
	// J'avoue j'ai pas tout compris pour ça mais chuuut on m'en veux pas
	return response.AccessToken, expirationTime, nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// No need to clear cookies or sessions in this case
	// Redirect the user to the login page or any other desired page
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if authenticateUser(username, password) {
			// Authentication successful
			// Set cookies/sessions if needed

			http.Redirect(w, r, "/success", http.StatusSeeOther)
			return
		}

		// Authentication failed
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Display the login form
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Error rendering login page", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error rendering login page", http.StatusInternalServerError)
		return
	}
}

func authenticateUser(username, password string) bool {
	// Simple authentication logic for demonstration purposes
	for _, user := range users {
		if user.Username == username && user.Password == password {
			return true
		}
	}
	return false
}

func loadUsersFromFile() {
	// Chargez les utilisateurs depuis le fichier JSON
	file, err := ioutil.ReadFile(usersFile)
	if err != nil {
		fmt.Println("Erreur lors de la lecture du fichier des utilisateurs:", err)
		return
	}

	err = json.Unmarshal(file, &users)
	if err != nil {
		fmt.Println("Erreur lors de la désérialisation du fichier des utilisateurs:", err)
		return
	}
}

func saveUsersToFile() {
	// Enregistrez les utilisateurs dans le fichier JSON
	usersJSON, err := json.MarshalIndent(users, "", "    ")
	if err != nil {
		fmt.Println("Erreur lors de la sérialisation des utilisateurs:", err)
		return
	}

	err = ioutil.WriteFile(usersFile, usersJSON, 0644)
	if err != nil {
		fmt.Println("Erreur lors de l'écriture dans le fichier des utilisateurs:", err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		if userExists(username) {
			http.Error(w, "Username already exists", http.StatusBadRequest)
			return
		}

		// Créez l'utilisateur et ajoutez-le à la liste des utilisateurs
		newUser := User{Username: username, Password: password}
		users = append(users, newUser)

		// Enregistrez les utilisateurs dans le fichier JSON
		saveUsersToFile()

		// Set cookies/sessions if needed

		http.Redirect(w, r, "/success", http.StatusSeeOther)
		return
	}

	// Affichez le formulaire d'inscription
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		http.Error(w, "Error rendering registration page", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error rendering registration page", http.StatusInternalServerError)
		return
	}
}

func userExists(username string) bool {
	for _, user := range users {
		if user.Username == username {
			return true
		}
	}
	return false
}
