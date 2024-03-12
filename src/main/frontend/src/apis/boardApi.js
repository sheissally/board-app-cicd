import { createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

export const getBoards = createAsyncThunk(
    'board/getBoards',
    async (search, thunkAPI) => {
        try {
            const response = await axios.get(
                `/board/board-list`,
                {
                    headers: {
                        Authorization: `Bearer ${sessionStorage.getItem("ACCESS_TOKEN")}`
                    },
                    params: {
                        searchCondition: search.searchCondition,
                        searchKeyword: search.searchKeyword,
                        page: search.page
                    }
                }
            );

            return response.data;
        } catch(e) {
            return thunkAPI.rejectWithValue(e);
        }
    }
);

export const postBoard = createAsyncThunk(
    'board/postBoard',
    async (board, thunkAPI) => {
        try {
            const response = await axios.post(
                `/board/board`,
                board,
                {
                    headers: {
                        Authorization: `Bearer ${sessionStorage.getItem("ACCESS_TOKEN")}`,
                        "Content-Type": "multipart/form-data"
                    }
                }
            );

            return response.data.pageItems;

        } catch(e) {
            return thunkAPI.rejectWithValue(e);
        }
    }
);

export const removeBoard = createAsyncThunk(
    'board/removeBoard',
    async (boardNo, thunkAPI) => {
        try {
            const response = await axios.delete(
                `/board/board/${boardNo}`,
                {
                    headers: {
                        Authorization: `Bearer ${sessionStorage.getItem("ACCESS_TOKEN")}`
                    }
                }
            );

            return response.data.pageItems;
        } catch(e) {
            return thunkAPI.rejectWithValue(e);
        }
    }
)