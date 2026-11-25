package http

import "libriary_system/rating_service/internal/domain"

type ratingResponse struct {
	Stars int `json:"stars"`
}

type setRatingRequest struct {
	Stars *int `json:"stars"`
}

type addStarsRequest struct {
	Delta *int `json:"delta"`
}

// Target identity is data, not caller identity. Only the scoped worker route
// accepts it; the public route always uses the verified JWT subject.
type internalAddStarsRequest struct {
	Username string `json:"username"`
	Delta    *int   `json:"delta"`
}

type errorResponse struct {
	Message string `json:"message"`
}

func toRatingResponse(rating domain.Rating) ratingResponse {
	return ratingResponse{Stars: rating.StarsCount}
}
