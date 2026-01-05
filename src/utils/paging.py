# src/utils/paging.py
from fastapi import Request
from pydantic import BaseModel, Field
from typing import Any, List, Dict, Optional


class Paging(BaseModel):
    page: int = 1                   # 현재 페이지
    page_size: int = 10             # 하단에 표시할 페이지 버튼 개수
    _page_total: int = 0            # 내부 저장용 (자동 계산)
    list_size: int = 10             # 한 페이지에 보여질 게시물 수
    _list_total: int = 0            # 내부 저장용 (자동 계산 트리거)
    search: Dict[str, Any] = {}     # 검색 조건
    content: List[Any] = []         # 현재 페이지의 게시물 리스트

    # ✅ 전체 게시물 수
    @property
    def list_total(self) -> int:
        return self._list_total

    @list_total.setter
    def list_total(self, value: int):
        self._list_total = value
        # 전체 페이지 자동 계산
        if self.list_size > 0:
            self._page_total = max((value + self.list_size - 1) // self.list_size, 1)
        else:
            self._page_total = 1

    # ✅ 전체 페이지 수
    @property
    def page_total(self) -> int:
        return self._page_total

    # ✅ 페이지 블록 계산 (1~10, 11~20 등)
    @property
    def start_page(self) -> int:
        return ((self.page - 1) // self.page_size) * self.page_size + 1

    @property
    def end_page(self) -> int:
        return min(self.start_page + self.page_size - 1, self.page_total)

    # ✅ 이전/다음 페이지 블록 존재 여부
    @property
    def has_prev(self) -> bool:
        return self.start_page > 1

    @property
    def has_next(self) -> bool:
        return self.end_page < self.page_total

    # ✅ FastAPI 의존성 (쿼리 파라미터 자동 매핑)
    @classmethod
    async def dep(
        cls,
        request: Request,
        list_total: int = 0,
        list_data: Optional[List[Any]] = None,
    ) -> "Paging":
        """
        ✅ 공통 페이징 유틸 (GET 파라미터 자동 인식)
        - request.query_params에서 page, list_size, page_size 추출
        - 나머지 파라미터는 search에 자동 포함
        """
        query = dict(request.query_params)

        page = int(query.pop("page", 1) or 1)
        list_size = int(query.pop("list_size", 10) or 10)
        page_size = int(query.pop("page_size", 10) or 10)
        search = query

        obj = cls(
            page=page,
            page_size=page_size,
            list_size=list_size,
            _list_total=list_total,
            search=search,
            content=list_data or [],
        )

        # ✅ 전체 페이지 계산 즉시 반영
        if list_total:
            obj.list_total = list_total

        return obj