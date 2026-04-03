package com.ev.batteryswap.services;
import com.ev.batteryswap.pojo.StationReview;
import com.ev.batteryswap.repositories.StationRepository;
import com.ev.batteryswap.repositories.StationReviewRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class StationReviewService {

    @Autowired
    private StationReviewRepository stationReviewRepository;


    public StationReview save(StationReview stationReview) {
        return stationReviewRepository.save(stationReview);
    }

}
